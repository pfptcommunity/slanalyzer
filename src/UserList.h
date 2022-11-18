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
#include <vector>

namespace Proofpoint {
class UserList {
	friend class UserAnalyzer;
public:
	struct Entry {
	  std::string givenName;
	  std::string sn;
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
	UserList();
	void Load(const std::string& list_file, UserErrors& entry_errors);
	void Save(const std::string& list_file);
private:
	std::vector<Entry> user_list;
	std::size_t address_count;
};
typedef UserList::UserErrors UserErrors;
}
#endif //SLANALYZER_USERSAFELIST_H
