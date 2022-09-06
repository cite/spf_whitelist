#!/usr/bin/env ruby

require 'dnsruby'
require 'ipaddress'
require 'logger'
require 'optparse'
require 'rubygems'

# collect networks to whitelist
networks = []

# parse parameters
params = ARGV.getopts("fi:l:o:")

$logger = Logger.new($stderr)
if params.has_key?("i") and params["l"].is_a?(String)
  loglevel = params["l"]
  begin
    $logger.level = loglevel
  rescue
    $logger.error("invalid log level #{loglevel}")
  end
else
  $logger.level = "DEBUG"
end

# input file
if params.has_key?("i") and params["i"].is_a?(String)
  domains = File.readlines(params["i"]).map(&:chomp)
  $logger.debug(domains)
else
  $logger.error("no file to read domains from given")
  exit(1)
end

# output file
if params.has_key?("o") and params["o"].is_a?(String)
  outfile = params["o"]
else
  outfile = "/tmp/spf_whitelist.cidr"
end

# get amount of lines in original file
old_lines = 0
begin
  old_lines = File.read(outfile).lines.count
rescue Exception => e
  $logger.warn("unable to read old output file #{outfile}, assuming -f")
  params["f"] = true
end

def a(names, resolver)
  result = []
  names.each do |name|
    begin
      records = resolver.getresources(name, "AAAA") + resolver.getresources(name, "A")
    rescue Dnsruby::ResolvError, Timeout::Error
      $logger.debug("no A result found for name #{name}")
      records = []
    end
    result += records.collect{|r| r.address.to_s.downcase}
  end
  return result
end

def ptr(name, resolver)
  begin
    records = resolver.getresources(name, "PTR")
  rescue Dnsruby::ResolvError, Timeout::Error
    $logger.debug("no PTR result found for name #{name}")
    records = []
  end
  return a(records.collect{|r| r.name}, resolver)
end

def mx(name, resolver)
  begin
    records = resolver.getresources(name, "MX")
  rescue Dnsruby::ResolvError, Timeout::Error
    $logger.debug("no MX result found for name #{name}")
    records = []
  end
  return a(records.collect{|r| r.exchange}, resolver)
end

def get_spf_results(domain, resolver)
  result = []
  begin
    records = resolver.getresources(domain, "TXT") + resolver.getresources(domain, "SPF")
  rescue Dnsruby::ResolvError, Timeout::Error
    records = []
  end
  records = records.collect{|r| r.strings.join}.uniq.select{|r| r.match(/^v=spf1/)}
  records.each do |line|
    line.split(/\s+/).each do |entry|
      next if entry == "v=spf1"
      if m = entry.match(/^redirect=(?<redirect>.*)/)
        return get_spf_results(m[:redirect], resolver)
      elsif m = entry.match(/^\??include:(?<include>.*)/)
        result += get_spf_results(m[:include], resolver)
      elsif m = entry.match(/^\??ip4:(?<ip4>.*)/)
        result += [m[:ip4]]
      elsif m = entry.match(/^\??ip6:(?<ip6>.*)/)
        result += [m[:ip6]]
      elsif m = entry.match(/^\??mx$/)          # mx
        result += mx(domain, resolver)
      elsif m = entry.match(/^\??mx:(?<mx>.*)/) # mx: <- ":"!!!
        result += mx(m[:mx], resolver)
      elsif m = entry.match(/^\??a$/)         # a
        result += a([domain], resolver)
      elsif m = entry.match(/^\??a:(?<a>.*)/) # a: <- ":"!!!
        result += a([m[:a]], resolver)
      elsif entry.match(/.all/)
        true
      else
        $logger.debug("unable to parse DNS entry #{entry}")
      end
    end
  end
  # some people don't seem to get netmasks right, so fix this
  result = result.map do |r|
    if m = r.match(/^(?<network>\d+\.\d+\.\d+\.\d+)\/(?<prefix>\d+)$/)
      i = IPAddress(r)
      i.network.address.to_s + "/" + i.network.prefix.to_s
    else
      # let's see if this is a valid IP address at all
      begin
        IPAddress(r).to_s
      rescue
        $logger.info("skipping entry #{r}")
        nil
      end
    end
  end
  $logger.debug(result)
  return result.compact.sort.uniq
end

# generate resolver
resolver = Dnsruby::DNS.open

# collect results, format as Postfix CIDR style map
spf_results = domains.collect{|d| get_spf_results(d, resolver)}.flatten.uniq.sort

# compare number of results
ratio = (old_lines.to_f / spf_results.count.to_f)
if (ratio < 0.9 or ratio > 1.1) and old_lines > 0
  $logger.warn("more than 10% difference in number of results detected, old: #{old_lines}, new: #{spf_results.count}")
  unless params.has_key?("f") and params["f"]
    $logger.fatal("call with -f to force writing")
    exit 1
  end
end

# write file
File.write(outfile, spf_results.join(" permit\n") + " permit\n")
