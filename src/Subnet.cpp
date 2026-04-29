#include "Subnet.h"

#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>

using namespace Proofpoint;

/* ---------- Static helpers ---------- */

bool Subnet::IsValidIp(const std::string& address)
{
    return RE2::FullMatch(address, ip_matcher);
}

bool Subnet::IsValidCidr(const std::string& cidr)
{
    std::string n, b;
    return IsValidCidr(cidr, n, b);
}

bool Subnet::IsValidCidr(const std::string& cidr,
                         std::string& network,
                         std::string& bits)
{
    re2::StringPiece net_part;
    re2::StringPiece bits_part;

    if (!RE2::FullMatch(cidr, cidr_matcher, &net_part, &bits_part))
        return false;

    network.assign(net_part.data(), net_part.size());
    bits.assign(bits_part.data(), bits_part.size());
    return true;
}

/* ---------- Constructors ---------- */

Subnet::Subnet(const std::string& cidr)
{
    std::string net_str, bits_str;
    if (!IsValidCidr(cidr, net_str, bits_str)) {
        throw SubnetArgumentException("Invalid CIDR: " + cidr);
    }

    in_addr net_addr{};
    if (inet_pton(AF_INET, net_str.c_str(), &net_addr) == 0) {
        throw SubnetArgumentException("Invalid network address: " + net_str);
    }

    int bits = std::stoi(bits_str);
    if (bits < 0 || bits > 32) {
        throw SubnetArgumentException("Invalid CIDR bits: " + bits_str);
    }

    net = ntohl(net_addr.s_addr);
    mask = bits == 0 ? 0 : (~0U << (32 - bits));

    min   = net & mask;
    max   = min | ~mask;
    bcast = max;
    wmask = ~mask;

    hosts = (bits >= 31) ? 0 : ((1U << (32 - bits)) - 2);
}

Subnet::Subnet(const std::string& network, const std::string& netmask)
{
    in_addr net_addr{}, mask_addr{};

    if (inet_pton(AF_INET, network.c_str(), &net_addr) == 0 ||
        inet_pton(AF_INET, netmask.c_str(), &mask_addr) == 0) {
        throw SubnetArgumentException("Invalid network or mask");
    }

    net  = ntohl(net_addr.s_addr);
    mask = ntohl(mask_addr.s_addr);

    min   = net & mask;
    max   = min | ~mask;
    bcast = max;
    wmask = ~mask;
    hosts = (mask == 0xFFFFFFFF) ? 0 : ((~mask) - 1);
}

Subnet::Subnet(const in_addr_t& network,
               const in_addr_t& netmask,
               ByteOrder order)
{
    net  = (order == NETWORK) ? ntohl(network) : network;
    mask = (order == NETWORK) ? ntohl(netmask) : netmask;

    min   = net & mask;
    max   = min | ~mask;
    bcast = max;
    wmask = ~mask;
    hosts = (mask == 0xFFFFFFFF) ? 0 : ((~mask) - 1);
}

/* ---------- Getters ---------- */

static std::string to_string(in_addr_t addr)
{
    in_addr a{ htonl(addr) };
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

std::string Subnet::GetNet() const { return to_string(net); }
std::string Subnet::GetMask() const { return to_string(mask); }
std::string Subnet::GetMin() const { return to_string(min); }
std::string Subnet::GetMax() const { return to_string(max); }
std::string Subnet::GetBroadcast() const { return to_string(bcast); }
std::string Subnet::GetWildcard() const { return to_string(wmask); }

in_addr_t Subnet::GetNetAddress(ByteOrder order) const
{
    return order == NETWORK ? htonl(net) : net;
}

in_addr_t Subnet::GetMaskAddress(ByteOrder order) const
{
    return order == NETWORK ? htonl(mask) : mask;
}

in_addr_t Subnet::GetMinAddress(ByteOrder order) const
{
    return order == NETWORK ? htonl(min) : min;
}

in_addr_t Subnet::GetMaxAddress(ByteOrder order) const
{
    return order == NETWORK ? htonl(max) : max;
}

in_addr_t Subnet::GetBroadcastAddress(ByteOrder order) const
{
    return order == NETWORK ? htonl(bcast) : bcast;
}

in_addr_t Subnet::GetWildcardAddress(ByteOrder order) const
{
    return order == NETWORK ? htonl(wmask) : wmask;
}

uint32_t Subnet::GetAddressableHosts() const
{
    return hosts;
}

