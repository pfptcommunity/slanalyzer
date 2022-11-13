/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slparser
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLPARSER_SRC_IMATCHER_H_
#define SLPARSER_SRC_IMATCHER_H_

#include <string>
#include <vector>

namespace Proofpoint {
class IMatcher {
 public:
  virtual void Add(const std::string &pattern, const std::size_t &index) = 0;
  virtual bool Match(const std::string &pattern, std::vector<std::size_t> &match_indexes) = 0;
  virtual std::size_t GetPatternCount() = 0;
};
}

#endif //SLPARSER_SRC_IMATCHER_H_
