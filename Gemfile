# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in active_storage_encryption.gemspec.
gemspec

# Start debugger with binding.b [https://github.com/ruby/debug]
# gem "debug", ">= 1.0.0"

# minitest 6 moved Minitest::Mock - and with it Object#stub, which the proxy controller test
# uses - out into a gem of its own, so `require "minitest/mock"` in the test helper fails on it.
gem "minitest", "< 6"
