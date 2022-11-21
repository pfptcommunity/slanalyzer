/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_IMATCHER_H
#define SLANALYZER_IMATCHER_H

#include <string>
#include <vector>

namespace Proofpoint {
template <typename T>
class IMatcher {
public:
	struct PatternError {
	  T index;
	  std::string pattern;
	  std::string error;
	};
	using PatternErrors = std::vector<PatternError> ;
public:
	virtual void Add(const std::string& pattern, const T& index, PatternErrors& pattern_errors) = 0;
	virtual bool Match(const std::string& pattern, std::vector<T>& match_indexes) = 0;
	virtual std::size_t GetPatternCount() = 0;
};
template<typename T>
using PatternErrors = typename IMatcher<T>::PatternErrors;
}

#endif //SLANALYZER_IMATCHER_H
