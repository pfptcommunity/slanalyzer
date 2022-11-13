/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slparser
 * @version 1.0.0
 * @license MIT
 */
#include "AddressMatcher.h"

Proofpoint::AddressMatcher::AddressMatcher() : StringMatcher() {}

void Proofpoint::AddressMatcher::Add(SafeList::SBMatchType type, const std::string &pattern, const std::size_t &index) {
  using
  enum SafeList::SBMatchType;
  switch (type) {
	case IP_IN_NET: in_subnets.emplace_back(std::make_shared<Subnet>(pattern), index);
	  break;
	case IP_NOT_IN_NET: not_in_subnets.emplace_back(std::make_shared<Subnet>(pattern), index);
	  break;
	default: StringMatcher::Add(type, pattern, index);
	  break;
  }
}
bool Proofpoint::AddressMatcher::Match(const std::string &pattern,
									   std::vector<std::shared_ptr<SafeList::SLEntry>> &safe_list) {
  bool matched = false;
  std::vector<std::size_t> match_indexes;
  for (auto s : in_subnets) {
	auto ptr = std::get<0>(s);
	auto index = std::get<1>(s);
	if (ptr->InSubnet(pattern)) {
	  safe_list[index]->matches++;
	  matched |= true;
	}
  }
  for (auto s : not_in_subnets) {
	auto ptr = std::get<0>(s);
	auto index = std::get<1>(s);
	if (!ptr->InSubnet(pattern)) {
	  safe_list[index]->matches++;
	  matched |= true;
	}
  }
  matched |= StringMatcher::Match(pattern, safe_list);
  return matched;
}
