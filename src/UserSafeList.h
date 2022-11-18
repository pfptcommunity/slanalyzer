/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#ifndef SLANALYZER_USERSAFELIST_H
#define SLANALYZER_USERSAFELIST_H
#include <string>
#include <memory>
#include <vector>

namespace Proofpoint {
class UserSafeList {
	friend class UserAnalyzer;
public:
	enum class FieldType {
	  UNKNOWN,
	  FROM,
	  HFROM
	};
	enum class MatchType {
	  UNKNOWN,
	  EMAIL,
	  DOMAIN,
	};
	struct UserEntry {
	  std::string fname;
	  std::string lname;
	  std::string mail;
	  std::vector<std::string> proxy_addresses;
	  std::vector<std::string> safe;
	  std::vector<std::string> block;
	  std::size_t safe_count;
	  std::size_t block_count;
	};
	struct UserError {
	  std::size_t index;
	  std::string error;
	};
	typedef std::vector<UserError> UserErrors;
public:
	UserSafeList() = default;
	void Load(const std::string& list_file, UserErrors& entry_errors);
	void Save(const std::string& list_file);
private:
	std::vector<std::shared_ptr<UserEntry>> user_list;
};
typedef UserSafeList::UserErrors UserErrors;
//typedef UserSafeList::MatchType MatchType;
//typedef UserSafeList::FieldType FieldType;
}
#endif //SLANALYZER_USERSAFELIST_H
