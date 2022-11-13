/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slparser
 * @version 1.0.0
 * @license MIT
 */
#include "Subnet.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include "re2/re2.h"

Proofpoint::Subnet::Subnet(const std::string &cidr)
	: min(0), max(0), wmask(0), hosts(0) {
  std::string network;
  std::string bits;
  if (!IsValidCidr(cidr, network, bits)) throw SubnetArgumentException("Invalid CIDR format [" + cidr + "]");

  unsigned long b = std::stoul(bits);

  in_addr net_address = {0};
  if (inet_aton(network.c_str(), &net_address)==0)
	throw SubnetArgumentException("Invalid network address format [" + network + "]");
  this->net = ntohl(net_address.s_addr);

  mask = (0xFFFFFFFFu << (32 - b));
  _validate();
}
Proofpoint::Subnet::Subnet(const std::string &network, const std::string &netmask) {
  if (!IsValidIp(network)) throw SubnetArgumentException("Invalid network address format [" + network + "]");
  if (!IsValidIp(netmask)) throw SubnetArgumentException("Invalid mask address format [" + netmask + "]");

  in_addr net_address = {0};
  in_addr mask_address = {0};

  if (inet_aton(network.c_str(), &net_address)==0)
	throw SubnetArgumentException("Invalid network address format [" + network + "]");
  if (inet_aton(netmask.c_str(), &mask_address)==0)
	throw SubnetArgumentException("Invalid mask address format [" + netmask + "]");

  // Stored on host side in host byte order
  this->net = ntohl(net_address.s_addr);
  this->mask = ntohl(mask_address.s_addr);
  _validate();
}
Proofpoint::Subnet::Subnet(const in_addr_t &network, const in_addr_t &netmask, Proofpoint::Subnet::ByteOrder order) {
  if (order==ByteOrder::HOST) {
	net = network;
	mask = netmask;
  } else {
	net = ntohl(network);
	mask = ntohl(netmask);
  }
  _validate();
}
bool Proofpoint::Subnet::InSubnet(in_addr_t address, Proofpoint::Subnet::ByteOrder order) const {
  // convert to host byte order
  if (order==ByteOrder::NETWORK) {
	address = ntohl(address);
  }
  return !((address ^ net) & mask);
}
bool Proofpoint::Subnet::InSubnet(const std::string &ip_address) const {
  //if (!IsValidIp(ip_address)) return false;
  in_addr address{0};
  if (inet_aton(ip_address.c_str(), &address)==0) return false;
  return !((ntohl(address.s_addr) ^ net) & mask);
}
std::string Proofpoint::Subnet::GetNet() const {
  return GetAddress(this->net);
}
std::string Proofpoint::Subnet::GetMask() const {
  return GetAddress(this->mask);
}
std::string Proofpoint::Subnet::GetMin() const {
  return GetAddress(this->min);
}
std::string Proofpoint::Subnet::GetMax() const {
  return GetAddress(this->max);
}
std::string Proofpoint::Subnet::GetBroadcast() const {
  return GetAddress(this->bcast);
}
std::string Proofpoint::Subnet::GetWildcard() const {
  return GetAddress(this->wmask);
}
in_addr_t Proofpoint::Subnet::GetNetAddress(Proofpoint::Subnet::ByteOrder order) const {
  return (order==ByteOrder::HOST) ? net : htonl(net);
}
in_addr_t Proofpoint::Subnet::GetMaskAddress(Proofpoint::Subnet::ByteOrder order) const {
  return (order==ByteOrder::HOST) ? mask : htonl(mask);
}
in_addr_t Proofpoint::Subnet::GetMinAddress(Proofpoint::Subnet::ByteOrder order) const {
  return (order==ByteOrder::HOST) ? min : htonl(min);
}
in_addr_t Proofpoint::Subnet::GetMaxAddress(Proofpoint::Subnet::ByteOrder order) const {
  return (order==ByteOrder::HOST) ? max : htonl(max);
}
in_addr_t Proofpoint::Subnet::GetBroadcastAddress(Proofpoint::Subnet::ByteOrder order) const {
  return (order==ByteOrder::HOST) ? bcast : htonl(bcast);
}
in_addr_t Proofpoint::Subnet::GetWildcardAddress(Proofpoint::Subnet::ByteOrder order) const {
  return (order==ByteOrder::HOST) ? wmask : htonl(wmask);
}
uint32_t Proofpoint::Subnet::GetAddressableHosts() const {
  return hosts;
}
void Proofpoint::Subnet::_validate() {
  if ((mask & (~mask >> 1))) {
	throw SubnetArgumentException("Invalid mask address [" + GetAddress(mask) + "]");
  }
  // Make sure the network ID is actually a network ID, we could throw an error
  // Eg. 192.168.1.0 = 192.168.1.2 (device) & 255.255.255.0 (mask)
  net = net & mask;
  wmask = ~mask;
  bcast = net | wmask;
  min = net + 1;
  max = bcast - 1;
  hosts = wmask - 1;
}
bool Proofpoint::Subnet::IsValidIp(const std::string &address) {
  return RE2::FullMatch(address,
						R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
}
bool Proofpoint::Subnet::IsValidCidr(const std::string &cidr, std::string &network, std::string &bits) {
  re2::StringPiece matches[255];
  RE2 re
	  (R"((?i)^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(\/(3[0-2]|2[0-9]|1[0-9]|[0-9]))$)");
  if (!re.Match(cidr, 0, cidr.length(), RE2::ANCHOR_BOTH, matches, 255)) return false;
  network = matches[1].ToString();
  bits = matches[6].ToString();
  return true;
}
bool Proofpoint::Subnet::IsValidCidr(const std::string &cidr) {
  return RE2::FullMatch(cidr,
						R"((?i)^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(\/(3[0-2]|2[0-9]|1[0-9]|[0-9]))$)");
}
bool Proofpoint::Subnet::IsNumber(const std::string &s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
}
std::string Proofpoint::Subnet::GetAddress(in_addr_t address, Proofpoint::Subnet::ByteOrder order) {
  char s[INET_ADDRSTRLEN];
  if (order==ByteOrder::HOST)
	address = htonl(address);
  inet_ntop(AF_INET, &address, s, INET_ADDRSTRLEN);
  return s;
}
