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

#include "IMatcher.h"
#include "GlobalList.h"
#include "Subnet.h"
#include "Utils.h"
#include <unordered_map>

namespace Proofpoint {
class GlobalAddressMatcher {
public:
	GlobalAddressMatcher();
	~GlobalAddressMatcher() = default;
	void Add(GlobalList::MatchType type, const std::string& pattern, const std::size_t& index, PatternErrors<std::size_t>& pattern_error);
	bool Match(bool inbound, const std::string& pattern, GlobalList::Entries& safe_list);
private:
	typedef std::vector<std::shared_ptr<Subnet>> SubnetCollection;
	typedef std::tuple<SubnetCollection, std::size_t> SubnetPair;
	std::vector<SubnetPair> in_subnets;
	std::vector<SubnetPair> not_in_subnets;
	std::unordered_map<GlobalList::MatchType, std::shared_ptr<IMatcher<std::size_t>>> matchers;
};
}
#endif //SLANALYZER_ADDRESSMATCHER_H