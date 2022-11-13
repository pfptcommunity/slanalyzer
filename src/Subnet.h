#ifndef SLPARSER_SUBNET_H
#define SLPARSER_SUBNET_H

#include <arpa/inet.h>
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
  static bool IsValidIp(const std::string &address);
  static bool IsValidCidr(const std::string &cidr, std::string &network, std::string &bits);
  static bool IsValidCidr(const std::string &cidr);
  static bool IsNumber(const std::string &s);
  static std::string GetAddress(in_addr_t address, ByteOrder order = HOST);
 public:
  explicit Subnet(const std::string &cidr);
  Subnet(const std::string &network, const std::string &netmask);
  Subnet(const in_addr_t &network, const in_addr_t &netmask, ByteOrder order);
  [[nodiscard]] bool InSubnet(in_addr_t address, ByteOrder order = HOST) const;
  [[nodiscard]] bool InSubnet(const std::string &ip_address) const;
  [[nodiscard]] std::string GetNet() const;
  [[nodiscard]] std::string GetMask() const;
  [[nodiscard]] std::string GetMin() const;
  [[nodiscard]] std::string GetMax() const;
  [[nodiscard]] std::string GetBroadcast() const;
  [[nodiscard]] std::string GetWildcard() const;
  [[nodiscard]] in_addr_t GetNetAddress(ByteOrder order = HOST) const;
  [[nodiscard]] in_addr_t GetMaskAddress(ByteOrder order = HOST) const;
  [[nodiscard]] in_addr_t GetMinAddress(ByteOrder order = HOST) const;
  [[nodiscard]] in_addr_t GetMaxAddress(ByteOrder order = HOST) const;
  [[nodiscard]] in_addr_t GetBroadcastAddress(ByteOrder order = HOST) const;
  [[nodiscard]] in_addr_t GetWildcardAddress(ByteOrder order = HOST) const;
  [[nodiscard]] uint32_t GetAddressableHosts() const;
 private:
  void _validate();

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
