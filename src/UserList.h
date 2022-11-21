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
#include <utility>
#include <vector>
#include <iterator>

namespace Proofpoint {
class UserList {
	friend class UserAnalyzer;
public:
	struct Entry {
	  struct ListItem {
		explicit ListItem(std::string pattern) : pattern(std::move(pattern)), hfrom_count(0), sender_count(0) {}
		std::string pattern;
		std::size_t hfrom_count;
		std::size_t sender_count;
	  };
	  std::string givenName;
	  std::string sn;
	  std::string mail;
	  std::vector<std::string> proxy_addresses;
	  std::vector<ListItem> safe;
	  std::vector<ListItem> block;
	  std::size_t safe_count;
	  std::size_t block_count;
	};
	using Entries = std::vector<Entry>;
	using iterator = Entries::iterator;
	using const_iterator = Entries::const_iterator;

	struct UserError {
	  std::size_t index;
	  std::string error;
	};
	using UserErrors = std::vector<UserError>;
public:
	UserList();
	void Load(const std::string& list_file, UserErrors& entry_errors);
	void Save(const std::string& list_file, bool extened);
public:
	[[nodiscard]] inline std::size_t GetUserCount() const { return entries.size(); }
	[[nodiscard]] inline std::size_t GetUserAddressCount() const { return user_address_count; }
	[[nodiscard]] inline std::size_t GetSafeListCount() const { return safe_list_count; }
	[[nodiscard]] inline std::size_t GetBlockListCount() const { return block_list_count; }
	[[nodiscard]] std::size_t GetSafeCount() const;
	[[nodiscard]] std::size_t GetBlockCount() const;
	iterator begin() { return entries.begin(); }
	iterator end() { return entries.end(); }
	[[nodiscard]] const_iterator begin() const { return entries.begin(); }
	[[nodiscard]] const_iterator end() const { return entries.end(); }
	[[nodiscard]] const_iterator cbegin() const { return entries.cbegin(); }
	[[nodiscard]] const_iterator cend() const { return entries.cend(); }
private:
	Entries entries;
	std::size_t user_address_count;
	std::size_t safe_list_count;
	std::size_t block_list_count;
};
typedef UserList::UserErrors UserErrors;
}
#endif //SLANALYZER_USERSAFELIST_H
