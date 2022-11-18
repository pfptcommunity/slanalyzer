/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_USERANALYZER_H
#define SLANALYZER_USERANALYZER_H

#include "UserSafeList.h"
#include "Matcher.h"
#include <memory>
#include <map>

namespace Proofpoint {
class UserAnalyzer {
public:
	explicit UserAnalyzer(const UserSafeList& safelist, PatternErrors& pattern_errors);
	~UserAnalyzer() = default;
	void Process(const std::string& ss_file, UserSafeList& safelist);
private:
	std::unordered_map<std::size_t,std::shared_ptr<Matcher>> safe_to_user;
	std::unordered_map<std::size_t,std::shared_ptr<Matcher>> block_to_user;
};
}
#endif //SLANALYZER_USERANALYZER_H
