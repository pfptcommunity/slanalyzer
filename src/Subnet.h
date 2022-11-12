#ifndef SLPARSER_SUBNET_H
#define SLPARSER_SUBNET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

namespace Proofpoint {
	class Subnet {
	public:
		class SubnetArgumentException : public std::invalid_argument {
			using std::invalid_argument::invalid_argument;
		};

		enum ByteOrder {
			NETWORK,
			HOST,
		};
	public:
		static bool IsValidIp(const std::string& address)
		{
			return RE2::FullMatch(address,
					R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
		}

		static bool IsValidCidr(const std::string& cidr, std::string& network, std::string& bits)
		{
			re2::StringPiece matches[255];
			RE2 re(R"((?i)^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(\/(3[0-2]|2[0-9]|1[0-9]|[0-9]))$)");
			if (!re.Match(cidr, 0, cidr.length(), RE2::ANCHOR_BOTH, matches, 255)) return false;
			network = matches[1].ToString();
			bits = matches[6].ToString();
			return true;
		}

		static bool IsValidCidr(const std::string& cidr)
		{
			return RE2::FullMatch(cidr,
					R"((?i)^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(\/(3[0-2]|2[0-9]|1[0-9]|[0-9]))$)");
		}

		static bool IsNumber(const std::string& s)
		{
			return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
		}

		static std::string GetAddress(in_addr_t address, ByteOrder order = HOST)
		{
			char s[INET_ADDRSTRLEN];
			if (order==ByteOrder::HOST)
				address = htonl(address);
			inet_ntop(AF_INET, &address, s, INET_ADDRSTRLEN);
			return s;
		}

	public:
		explicit Subnet(const std::string& cidr)
				:min(0), max(0), wmask(0), hosts(0)
		{
			std::string network;
			std::string bits;
			if (!IsValidCidr(cidr, network, bits)) throw SubnetArgumentException("Invalid CIDR format ["+cidr+"]");

			unsigned long b = std::stoul(bits);

			in_addr net_address = { 0 };
			if (inet_aton(network.c_str(), &net_address)==0)
				throw SubnetArgumentException("Invalid network address format ["+network+"]");
			this->net = ntohl(net_address.s_addr);

			mask = (0xFFFFFFFFu << (32-b));
			_validate();
		}

		Subnet(const std::string& network, const std::string& netmask)
		{
			if (!IsValidIp(network)) throw SubnetArgumentException("Invalid network address format ["+network+"]");
			if (!IsValidIp(netmask)) throw SubnetArgumentException("Invalid mask address format ["+netmask+"]");

			in_addr net_address = { 0 };
			in_addr mask_address = { 0 };

			if (inet_aton(network.c_str(), &net_address)==0)
				throw SubnetArgumentException("Invalid network address format ["+network+"]");
			if (inet_aton(netmask.c_str(), &mask_address)==0)
				throw SubnetArgumentException("Invalid mask address format ["+netmask+"]");

			// Stored on host side in host byte order
			this->net = ntohl(net_address.s_addr);
			this->mask = ntohl(mask_address.s_addr);
			_validate();
		}

		// Internally everything is stored via network byte order
		Subnet(const in_addr_t& network, const in_addr_t& netmask, ByteOrder order)
		{
			if (order==ByteOrder::HOST) {
				net = network;
				mask = netmask;
			}
			else {
				net = ntohl(network);
				mask = ntohl(netmask);
			}
			_validate();
		}

		[[nodiscard]] bool InSubnet(in_addr_t address, ByteOrder order = HOST) const
		{
			// convert to host byte order
			if (order==ByteOrder::NETWORK) {
				address = ntohl(address);
			}
			return !((address ^ net) & mask);
		}

		[[nodiscard]] bool InSubnet(const std::string& ip_address) const
		{
			//if (!IsValidIp(ip_address)) return false;
			in_addr address{ 0 };
			if (inet_aton(ip_address.c_str(), &address)==0) return false;
			return !((ntohl(address.s_addr) ^ net) & mask);
		}

		[[nodiscard]] std::string GetNet() const
		{
			return GetAddress(this->net);
		}

		[[nodiscard]] std::string GetMask() const
		{
			return GetAddress(this->mask);
		}

		[[nodiscard]] [[nodiscard]] std::string GetMin() const
		{
			return GetAddress(this->min);
		}

		[[nodiscard]] std::string GetMax() const
		{
			return GetAddress(this->max);
		}

		[[nodiscard]] std::string GetBroadcast() const
		{
			return GetAddress(this->bcast);
		}

		[[nodiscard]] std::string GetWildcard() const
		{
			return GetAddress(this->wmask);
		}

		[[nodiscard]] in_addr_t GetNetAddress(ByteOrder order = HOST) const
		{
			return (order==ByteOrder::HOST) ? net : htonl(net);
		}

		[[nodiscard]] in_addr_t GetMaskAddress(ByteOrder order = HOST) const
		{
			return (order==ByteOrder::HOST) ? mask : htonl(mask);
		}

		[[nodiscard]] in_addr_t GetMinAddress(ByteOrder order = HOST) const
		{
			return (order==ByteOrder::HOST) ? min : htonl(min);
		}

		[[nodiscard]] in_addr_t GetMaxAddress(ByteOrder order = HOST) const
		{
			return (order==ByteOrder::HOST) ? max : htonl(max);
		}

		[[nodiscard]] in_addr_t GetBroadcastAddress(ByteOrder order = HOST) const
		{
			return (order==ByteOrder::HOST) ? bcast : htonl(bcast);
		}

		[[nodiscard]] in_addr_t GetWildcardAddress(ByteOrder order = HOST) const
		{
			return (order==ByteOrder::HOST) ? wmask : htonl(wmask);
		}

		[[nodiscard]] uint32_t GetAddressableHosts() const
		{
			return hosts;
		}

	private:
		void _validate()
		{
			if ((mask & (~mask >> 1))) {
				throw SubnetArgumentException("Invalid mask address ["+GetAddress(mask)+"]");
			}
			// Make sure the network ID is actually a network ID, we could throw an error
			// Eg. 192.168.1.0 = 192.168.1.2 (device) & 255.255.255.0 (mask)
			net = net & mask;
			wmask = ~mask;
			bcast = net | wmask;
			min = net+1;
			max = bcast-1;
			hosts = wmask-1;
		}

	private:
		// Network Address (host order)
		in_addr_t net;
		// Subnet Mask (host order)
		in_addr_t mask;
		// Lowest Address (host order)
		in_addr_t min{};
		// Highest Address
		in_addr_t max{};
		// Broadcast
		in_addr_t bcast{};
		// Wildcard
		in_addr_t wmask{};
		// Maximum addressable
		uint32_t hosts{};
	};
}
#endif //SLPARSER_SUBNET_H
