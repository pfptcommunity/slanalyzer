/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_ADDRESSMATCHER_H
#define SLANALYZER_ADDRESSMATCHER_H

#include "Subnet.h"
#include "StringMatcher.h"

namespace Proofpoint {
class AddressMatcher : public IListMatcher {
public:
	AddressMatcher();
	~AddressMatcher() = default;
	void Add(SafeList::MatchType type, const std::string& pattern, const std::size_t& index,
			PatternErrors& pattern_errors) final;
	bool Match(bool inbound, const std::string& pattern,
			std::vector<std::shared_ptr<SafeList::Entry>>& safe_list) final;
private:
	typedef std::vector<std::shared_ptr<Subnet>> SubnetCollection;
	typedef std::tuple<SubnetCollection, std::size_t> SubnetPair;
	std::vector<SubnetPair> in_subnets;
	std::vector<SubnetPair> not_in_subnets;
	std::unordered_map<SafeList::MatchType, std::shared_ptr<IMatcher>> matchers;
};
}
#endif //SLANALYZER_ADDRESSMATCHER_H