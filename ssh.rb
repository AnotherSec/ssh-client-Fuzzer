class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer

  Rank = ManualRanking

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SSH Client Protocol Fuzzer',
      'Description'    => %q{
        SSH server yang fuzz SSH clients seperti OpenSSH, PuTTY, Bitvise, WinSCP.
        Target parsing bugs di KEXINIT, NEWKEYS, SERVICE_ACCEPT, USERAUTH, CHANNEL.
        
        Test dengan: ssh -p 2222 test@127.0.0.1
      },
      'Author'         => [ 'AnotherSecurity' ],
      'License'        => MSF_LICENSE,
      'References'     => [
        [ 'URL', 'https://tools.ietf.org/html/rfc4253' ]
      ],
      'Platform'       => 'all'
    ))

    register_options([
      OptPort.new('SRVPORT', [ true, 'SSH listen port', 2222 ]),
      OptString.new('FUZZTARGETS', [ false, 'Fuzz targets (comma sep)', 'kexinit,newkeys,service,auth,channel' ]),
      OptInt.new('STARTSIZE', [ true, 'Start fuzz size', 256 ]),
      OptInt.new('MAXSIZE', [ true, 'Max fuzz size', 1048576 ]),
      OptInt.new('STEP', [ true, 'Fuzz step size', 512 ])
    ])

    register_advanced_options([
      OptBool.new('CYCLIC', [ true, 'Use cyclic patterns (DEADBEEF)', true ]),
      OptString.new('BANNER', [ true, 'SSH server banner', 'SSH-2.0-OpenSSH_9.3' ])
    ])
  end

  def setup
    super
    @fuzz_size = datastore['STARTSIZE']
    @clients = {}
    @target_stats = {}
  end

  def run
    print_status("SSH Client Fuzzer listening on 0.0.0.0:#{datastore['SRVPORT']}")
    exploit
  end

  # Client connect
  def on_client_connect(client)
    ip = client.peerhost
    port = client.peerport
    
    @clients[client] = {
      ip: ip,
      port: port,
      state: :version,
      fuzzed: false,
      connect_time: Time.now
    }
    
    print_good("New SSH client connected: #{ip}:#{port}")
  
    banner = "#{datastore['BANNER']}\r\n"
    client.put(banner)
  end

  
  def on_client_data(client)
    return if @clients[client][:fuzzed]
    
    data = client.get_once(-1, 10)
    return unless data && !data.empty?
    
    info = @clients[client]
    
    case info[:state]
    when :version
      handle_version_exchange(client, data, info)
    when :kex
      handle_kex_exchange(client, data, info)
    when :service
      handle_service_request(client, data, info)
    when :auth
      handle_auth_request(client, data, info)
    end
  end

  # Client disconnect
  def on_client_close(client)
    info = @clients[client]
    if info
      duration = Time.now - info[:connect_time]
      if info[:fuzzed]
        print_good("FUZZ SUCCESS: #{info[:ip]}:#{info[:port]} crashed after #{duration.round(1)}s")
        update_stats(info[:last_fuzz_target])
      else
        print_status("Client #{info[:ip]}:#{info[:port]} disconnected (#{duration.round(1)}s)")
      end
    end
    @clients.delete(client)
  end

  def handle_version_exchange(client, data, info)
    if data.strip =~ /^SSH-2\.0-/
      print_status("Client version: #{data.strip}")
      info[:client_version] = data.strip
      info[:state] = :kex
      
      
      fuzz_kexinit(client, info)
    end
  end

  def handle_kex_exchange(client, data, info)
    fuzz_newkeys(client, info)
  end

  def handle_service_request(client, data, info)
    fuzz_service_accept(client, info)
  end

  def handle_auth_request(client, data, info)
    fuzz_auth_response(client, info)
  end

  # Fuzz handlers
  def fuzz_kexinit(client, info)
    if fuzz_target?('kexinit')
      payload = generate_payload('kexinit')
      packet = build_ssh_packet(20, payload) # SSH_MSG_KEXINIT
      send_fuzz_packet(client, packet, info, 'KEXINIT')
    end
  end

  def fuzz_newkeys(client, info)
    if fuzz_target?('newkeys')
      payload = generate_payload('newkeys')
      packet = build_ssh_packet(21, payload) # SSH_MSG_NEWKEYS
      send_fuzz_packet(client, packet, info, 'NEWKEYS')
    end
  end

  def fuzz_service_accept(client, info)
    if fuzz_target?('service')
      service_name = "ssh-userauth"
      payload = service_name + generate_payload('service')
      packet = build_ssh_packet(51, payload) # SSH_MSG_SERVICE_ACCEPT
      send_fuzz_packet(client, packet, info, 'SERVICE_ACCEPT')
    end
  end

  def fuzz_auth_response(client, info)
    if fuzz_target?('auth')
      payload = generate_payload('auth')
      packet = build_ssh_packet(52, payload) # SSH_MSG_USERAUTH_SUCCESS
      send_fuzz_packet(client, packet, info, 'AUTH_SUCCESS')
    end
  end

  # SSH Binary Packet Builder
  def build_ssh_packet(msg_type, payload)
    # Calculate padding
    block_size = 16
    inner_len = payload.length + 1 + 4 # payload + type + padlen
    pad_len = block_size - (inner_len % block_size)
    pad_len = [pad_len, 4].max # Minimum 4 bytes padding
    
    # Packet components
    packet_len = inner_len + pad_len
    mac_len = 20 # Placeholder
    
    len_bytes = [packet_len].pack('N')
    pad_len_byte = [pad_len].pack('C')
    type_byte = [msg_type].pack('C')
    padding = Rex::Text.rand_text_alpha(pad_len)
    mac = "\x00" * mac_len
    
    # Full SSH packet
    "#{len_bytes}#{pad_len_byte}#{type_byte}#{payload}#{padding}#{mac}"
  end

  def send_fuzz_packet(client, packet, info, target)
    print_status("#{target} fuzz (#{packet.length}B, #{@fuzz_size} payload) → #{info[:ip]}:#{info[:port]}")
    
    client.put(packet)
    info[:fuzzed] = true
    info[:last_fuzz_target] = target
    
    increment_fuzz_size
  end

  def fuzz_target?(target)
    return true unless datastore['FUZZTARGETS']
    datastore['FUZZTARGETS'].split(',').map(&:strip).include?(target)
  end

  def generate_payload(target)
    size = [@fuzz_size, 1024].min # Cap payload size
    if datastore['CYCLIC']
      Rex::Text.pattern_create(size)
    else
      Rex::Text.random_text_alpha(size)
    end
  end

  def increment_fuzz_size
    @fuzz_size += datastore['STEP']
    if @fuzz_size > datastore['MAXSIZE']
      print_status("Fuzz cycle complete. Reset to STARTSIZE (#{datastore['STARTSIZE']})")
      @fuzz_size = datastore['STARTSIZE']
    end
  end

  def update_stats(target)
    @target_stats[target] ||= 0
    @target_stats[target] += 1
    print_status("Stats: #{target} = #{@target_stats[target]} crashes")
  end
end
