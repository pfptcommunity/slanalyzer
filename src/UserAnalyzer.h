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

#include "UserList.h"
#include "Matcher.h"
#include <memory>
#include <cstring>
#include <map>

namespace Proofpoint {
class UserAnalyzer {
public:
	struct case_insensitive_unordered_map {
	  struct comp {
		bool operator() (const std::string& lhs, const std::string& rhs) const {
			return strcasecmp(lhs.c_str(), rhs.c_str()) == 0;
		}
	  };
	  struct hash {
		std::size_t operator() (std::string str) const {
			for (std::size_t index = 0; index < str.size(); ++index) {
				auto ch = static_cast<unsigned char>(str[index]);
				str[index] = static_cast<unsigned char>(std::tolower(ch));
			}
			return std::hash<std::string>{}(str);
		}
	  };
	};
	struct UserMatch{
	  std::size_t user_index;
	  std::size_t list_index;
	};
	using UserIndex = std::size_t;
public:
	UserAnalyzer() = default;
	~UserAnalyzer() = default;
	void Load(const UserList& safelist, PatternErrors<UserMatch>& pattern_errors);
	std::size_t Process(const std::string& ss_file, UserList& safelist, std::size_t& records_processed );
private:
	std::unordered_map<std::string,UserIndex,case_insensitive_unordered_map::hash,case_insensitive_unordered_map::comp> addr_to_user;
	std::unordered_map<UserIndex,std::shared_ptr<Matcher<UserMatch>>> safe_matcher;
	std::unordered_map<UserIndex,std::shared_ptr<Matcher<UserMatch>>> block_matcher;
};
}
#endif //SLANALYZER_USERANALYZER_H
