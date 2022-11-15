/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "Subnet.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include "re2/re2.h"

Proofpoint::Subnet::Subnet(const std::string& cidr)
		:min(0), max(0), wmask(0), hosts(0)
{
	re2::StringPiece matches[3];

	if (!cidr_matcher.Match(cidr, 0, cidr.length(), RE2::ANCHOR_BOTH, matches, 3)) throw SubnetArgumentException("Invalid CIDR format ["+cidr+"]");

	unsigned long b = std::stoul(matches[1].ToString());

	in_addr net_address = {0};
	if (inet_aton(matches[2].ToString().c_str(), &net_address)==0)
		throw SubnetArgumentException("Invalid network address format [" + matches[1].ToString() + "]");

	this->net = ntohl(net_address.s_addr);

	mask = (0xFFFFFFFFu << (32-b));
	net = net & mask;
	wmask = ~mask;
	bcast = net | wmask;
	min = net+1;
	max = bcast-1;
	hosts = wmask-1;
}
Proofpoint::Subnet::Subnet(const std::string& network, const std::string& netmask)
{
	in_addr net_address = {0};
	in_addr mask_address = {0};

	if (inet_aton(network.c_str(), &net_address)==0)
		throw SubnetArgumentException("Invalid network address format ["+ network +"]");

	if (inet_aton(netmask.c_str(), &mask_address)==0)
		throw SubnetArgumentException("Invalid mask address format ["+ netmask +"]");

	this->net = ntohl(net_address.s_addr);

	this->mask = ntohl(mask_address.s_addr);

	if ((mask & (~mask >> 1))) {
		throw SubnetArgumentException("Invalid mask address ["+ GetAddress(mask) +"]");
	}
	net = net & mask;
	wmask = ~mask;
	bcast = net | wmask;
	min = net+1;
	max = bcast-1;
	hosts = wmask-1;
}
Proofpoint::Subnet::Subnet(const in_addr_t& network, const in_addr_t& netmask, Proofpoint::Subnet::ByteOrder order)
{
	if (order==ByteOrder::HOST) {
		net = network;
		mask = netmask;
	}
	else {
		net = ntohl(network);
		mask = ntohl(netmask);
	}
	net = net & mask;
	wmask = ~mask;
	bcast = net | wmask;
	min = net+1;
	max = bcast-1;
	hosts = wmask-1;
}
bool Proofpoint::Subnet::InSubnet(in_addr_t address, Proofpoint::Subnet::ByteOrder order) const
{
	if (order==ByteOrder::NETWORK) {
		address = ntohl(address);
	}
	return !((address ^ net) & mask);
}
bool Proofpoint::Subnet::InSubnet(const std::string& ip_address) const
{
	in_addr address{0};
	if (inet_aton(ip_address.c_str(), &address)==0) return false;
	return !((ntohl(address.s_addr) ^ net) & mask);
}
std::string Proofpoint::Subnet::GetNet() const
{
	return GetAddress(this->net);
}
std::string Proofpoint::Subnet::GetMask() const
{
	return GetAddress(this->mask);
}
std::string Proofpoint::Subnet::GetMin() const
{
	return GetAddress(this->min);
}
std::string Proofpoint::Subnet::GetMax() const
{
	return GetAddress(this->max);
}
std::string Proofpoint::Subnet::GetBroadcast() const
{
	return GetAddress(this->bcast);
}
std::string Proofpoint::Subnet::GetWildcard() const
{
	return GetAddress(this->wmask);
}
in_addr_t Proofpoint::Subnet::GetNetAddress(Proofpoint::Subnet::ByteOrder order) const
{
	return (order==ByteOrder::HOST) ? net : htonl(net);
}
in_addr_t Proofpoint::Subnet::GetMaskAddress(Proofpoint::Subnet::ByteOrder order) const
{
	return (order==ByteOrder::HOST) ? mask : htonl(mask);
}
in_addr_t Proofpoint::Subnet::GetMinAddress(Proofpoint::Subnet::ByteOrder order) const
{
	return (order==ByteOrder::HOST) ? min : htonl(min);
}
in_addr_t Proofpoint::Subnet::GetMaxAddress(Proofpoint::Subnet::ByteOrder order) const
{
	return (order==ByteOrder::HOST) ? max : htonl(max);
}
in_addr_t Proofpoint::Subnet::GetBroadcastAddress(Proofpoint::Subnet::ByteOrder order) const
{
	return (order==ByteOrder::HOST) ? bcast : htonl(bcast);
}
in_addr_t Proofpoint::Subnet::GetWildcardAddress(Proofpoint::Subnet::ByteOrder order) const
{
	return (order==ByteOrder::HOST) ? wmask : htonl(wmask);
}
uint32_t Proofpoint::Subnet::GetAddressableHosts() const
{
	return hosts;
}
bool Proofpoint::Subnet::IsValidIp(const std::string& address)
{
	return RE2::FullMatch(address,ip_matcher);
}
bool Proofpoint::Subnet::IsValidCidr(const std::string& cidr, std::string& network, std::string& bits)
{
	re2::StringPiece matches[3];
	if (!cidr_matcher.Match(cidr, 0, cidr.length(), RE2::ANCHOR_BOTH, matches, 3)) return false;
	network = matches[1].ToString();
	bits = matches[2].ToString();
	return true;
}
bool Proofpoint::Subnet::IsValidCidr(const std::string& cidr)
{
	return RE2::FullMatch(cidr,cidr_matcher);
}
std::string Proofpoint::Subnet::GetAddress(in_addr_t address, Proofpoint::Subnet::ByteOrder order)
{
	char s[INET_ADDRSTRLEN];
	if (order==ByteOrder::HOST)
		address = htonl(address);
	inet_ntop(AF_INET, &address, s, INET_ADDRSTRLEN);
	return s;
}
