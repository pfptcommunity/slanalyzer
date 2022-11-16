/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLPARSER_SRC_ILISTMATCHER_H_
#define SLPARSER_SRC_ILISTMATCHER_H_

#include "SafeList.h"
#include "IMatcher.h"

namespace Proofpoint {
class IListMatcher {
public:
	virtual void Add(SafeList::MatchType type,
			const std::string& pattern,
			const std::size_t& index,
			PatternErrors& errors) = 0;
	virtual bool Match(bool inbound, const std::string& pattern, std::vector<std::shared_ptr<SafeList::Entry>>& safe_list) = 0;
};
}
#endif //SLPARSER_SRC_ILISTMATCHER_H_
