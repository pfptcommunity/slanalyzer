/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLPARSER_ADDRESSMATCHER_H
#define SLPARSER_ADDRESSMATCHER_H

#include "Subnet.h"
#include "StringMatcher.h"

namespace Proofpoint {
class AddressMatcher : StringMatcher {
 public:
  AddressMatcher();
  ~AddressMatcher() = default;
  void Add(SafeList::SBMatchType type, const std::string &pattern, const std::size_t &index) override;
  bool Match(const std::string &pattern, std::vector<std::shared_ptr<SafeList::SLEntry>> &safe_list) override;
 private:
  std::vector<std::tuple<std::shared_ptr<Subnet>, std::size_t>> in_subnets;
  std::vector<std::tuple<std::shared_ptr<Subnet>, std::size_t>> not_in_subnets;
};
}
#endif //SLPARSER_ADDRESSMATCHER_H