# frozen_string_literal: true

# Copyright (c) 2024 Rails Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

require 'logger'
require 'fileutils'
require 'singleton'

module ActiveSupport
  class TaggedLogging
    include Singleton

    SEVERITIES = %i[debug info warn error fatal unknown].freeze
    DEFAULT_FORMAT = "%s [%s] %s -- %s: %s\n"

    attr_reader :logger, :tags

    def initialize
      @logger = ::Logger.new($stdout)
      @logger.formatter = method(:default_formatter)
      @tags = []
      @mutex = Mutex.new
    end

    def tagged(*new_tags, &block)
      @mutex.synchronize do
        @tags.concat(new_tags.flatten)
        result = block.call(self)
        @tags.pop(new_tags.flatten.size)
        result
      end
    end

    SEVERITIES.each do |severity|
      define_method(severity) do |message = nil, &block|
        message = block.call if block
        return if message.nil?

        formatted_tags = @tags.map { |t| "[#{t}]" }.join(" ")
        @logger.send(severity, "#{formatted_tags} #{message}".strip)
      end
    end

    def silence(temporary_level = ::Logger::ERROR, &block)
      old_level = @logger.level
      @logger.level = temporary_level
      yield self
    ensure
      @logger.level = old_level
    end

    private

    def default_formatter(severity, datetime, progname, msg)
      format(DEFAULT_FORMAT,
             severity[0],
             datetime.strftime("%Y-%m-%dT%H:%M:%S.%6N"),
             $$,
             progname,
             msg)
    end
  end
end