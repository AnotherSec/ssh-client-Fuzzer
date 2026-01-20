class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::TcpServer
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'SSH Client Protocol Fuzzer',
      'Description' => %q{
        SSH server yang fuzz SSH clients (OpenSSH, PuTTY, Bitvise, dll).
      },
      'Author'      => [ 'AnotherSecurity' ],
      'License'     => MyselfVenom
    ))

    register_options([
      OptPort.new('SRVPORT', [true, 'SSH listen port', 2222]),
      OptString.new('FUZZTARGETS', [true, 'Fuzz targets (comma sep)', 'kexinit,newkeys,service,auth,channel', nil]),
      OptInt.new('STARTSIZE', [true, 'Start fuzz size', 256]),
      OptInt.new('MAXSIZE', [true, 'Max fuzz size', 1048576]),
      OptInt.new('STEP', [true, 'Fuzz step size', 256]),
      OptBool.new('CYCLIC', [true, 'Use cyclic patterns', true]),
      OptString.new('BANNER', [true, 'SSH Banner', 'SSH-2.0-OpenSSH_9.3'])
    ])
  end

  def setup
    @fuzz_size = datastore['STARTSIZE']
    @clients = {}
    @ssh_packet_id = 0
  end

  def run
    print_status("SSH Fuzzer listening on 0.0.0.0:#{datastore['SRVPORT']}")
    exploit
  end

  def on_client_connect(client)
    ip = client.peerhost
    port = client.peerport
    
    @clients[client] = {
      ip: ip,
      port: port,
      state: :version,
      packet_id: 0,
      crashed: false
    }
    
    print_good("New SSH client: #{ip}:#{port}")
    
    banner = "#{datastore['BANNER']}\r\n"
    client.put(banner)
  end

  def on_client_data(client)
    return if @clients[client][:crashed]
    
    data = client.get_once(-1, 3)
    return if !data || data.empty?
    
    client_info = @clients[client]
    
    case client_info[:state]
    when :version
      handle_version_exchange(client, data, client_info)
    when :kex
      handle_key_exchange(client, data, client_info)
    when :service
      handle_service_request(client, data, client_info)
    when :auth
      handle_auth(client, data, client_info)
    else
      fuzz_generic_response(client, client_info)
    end
  end

  def on_client_close(client)
    info = @clients[client]
    if info && !info[:crashed]
      print_status("Client #{info[:ip]}:#{info[:port]} disconnected")
    end
    @clients.delete(client)
  end

  def handle_version_exchange(client, data, info)
    if data =~ /^SSH-2\.0-/
      print_status("Client version: #{data.strip}")
      info[:client_version] = data.strip
      info[:state] = :kex
    
      fuzz_kexinit(client, info)
    end
  end

  def handle_key_exchange(client, data, info)
    fuzz_kex_response(client, info)
  end

  def handle_service_request(client, data, info)
    fuzz_service_accept(client, info)
    info[:state] = :auth
  end

  def handle_auth(client, data, info)
    fuzz_auth_response(client, info)
  end

  def fuzz_kexinit(client, info)
    if should_fuzz('kexinit', info)
      payload = generate_fuzz_payload('kexinit')
      packet = ssh_packet(20, payload) # SSH_MSG_KEXINIT
      send_packet(client, packet, info, 'KEXINIT')
    end
  end

  def fuzz_kex_response(client, info)
    if should_fuzz('newkeys', info)
      payload = generate_fuzz_payload('newkeys')
      packet = ssh_packet(21, payload) # SSH_MSG_NEWKEYS
      send_packet(client, packet, info, 'NEWKEYS')
    end
  end

  def fuzz_service_accept(client, info)
    if should_fuzz('service', info)
      payload = "ssh-userauth" + generate_fuzz_payload('service')
      packet = ssh_packet(51, payload) # SSH_MSG_SERVICE_ACCEPT
      send_packet(client, packet, info, 'SERVICE_ACCEPT')
    end
  end

  def fuzz_auth_response(client, info)
    if should_fuzz('auth', info)
      payload = generate_fuzz_payload('auth')
      packet = ssh_packet(52, payload) # SSH_MSG_USERAUTH_SUCCESS
      send_packet(client, packet, info, 'AUTH_SUCCESS')
    end
  end

  def fuzz_generic_response(client, info)
    if should_fuzz('channel', info)
      payload = generate_fuzz_payload('channel')
      packet = ssh_packet(90, payload) # SSH_MSG_CHANNEL_OPEN
      send_packet(client, packet, info, 'CHANNEL_OPEN')
    end
  end

  def ssh_packet(msg_type, payload)
    mac = "\x00" * 20
    
    payload_len = payload.length + 1 + 4 # type + length + padding_length
    len_bytes = [payload_len].pack('N')
    
    block_size = 16
    padding_len = block_size - (payload_len % block_size)
    padding = Rex::Text.rand_text_alpha(padding_len)
    pad_len_byte = [padding_len].pack('C')
    
    data = len_bytes + pad_len_byte + [msg_type].pack('C') + payload + padding + mac
    
    data
  end

  def send_packet(client, packet, info, msg_type)
    print_status("#{msg_type} fuzz (#{@fuzz_size}B) -> #{info[:ip]}:#{info[:port]}")
    client.put(packet)
    
    info[:crashed] = true
    increment_fuzz
  end

  def should_fuzz(target, info)
    targets = datastore['FUZZTARGETS'].split(',')
    targets.include?(target)
  end

  def generate_fuzz_payload(target)
    if datastore['CYCLIC']
      Rex::Text.pattern_create(@fuzz_size)
    else
      Rex::Text.random_text(@fuzz_size)
    end
  end

  def increment_fuzz
    @fuzz_size += datastore['STEP']
    if @fuzz_size > datastore['MAXSIZE']
      print_status("Reset fuzz size to STARTSIZE")
      @fuzz_size = datastore['STARTSIZE']
    end
  end
end
