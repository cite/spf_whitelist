#!/usr/bin/env ruby

require 'rubygems'
require 'dnsruby'
require 'ipaddress'
require 'optparse'

domains = [
  # freemail provider
  "gmail.com",
  "googlemail.com",
  "gmx.net",
  "gmx.com",
  "gmx.de",
  "web.de",
  "google.com",
  "aol.com",
  "microsoft.com",
  # social stuff
  "facebook.com",
  "twitter.com",
  "pinterest.com",
  "instagram.com",
  "reddit.com",
  "linkedin.com",
  "xing.com",
  "xing.de",
  # commerce hosts
  "amazon.com",
  "amazon.de",
  "ebay.de",
  "ebay.com",
  "paypal.com",
  "paypal.de",
  # bulk sender
  "sendgrid.com",
  "sendgrid.net",
  "mailchimp.com",
  "exacttarget.com",
  "cust-spf.exacttarget.com",
  "constantcontact.com",
  "icontact.com",
  "mailgun.com",
  "fishbowl.com",
  "fbmta.com",
  "mailjet.com",
  "sparkpost.com",
  "sparkpostmail.com",
  # misc stuff
  "github.com",
]

# collect networks to whitelist
networks = []

# parse parameters
params = ARGV.getopts("o:f")

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
  true
end

def a(names, resolver)
  result = []
  names.each do |name|
    begin
      records = resolver.getresources(name, "AAAA") + resolver.getresources(name, "A")
    rescue Dnsruby::ResolvError, Timeout::Error
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
    records = []
  end
  return a(records.collect{|r| r.name}, resolver)
end

def mx(name, resolver)
  begin
    records = resolver.getresources(name, "MX")
  rescue Dnsruby::ResolvError, Timeout::Error
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
        # puts "ERROR: domain #{domain}, entry #{entry}"
      end
    end
  end
  # some people don't seem to get netmasks right, so fix this
  result = result.map do |r|
    if m = r.match(/^(?<network>\d+\.\d+\.\d+\.\d+)\/(?<prefix>\d+)$/)
      i = IPAddress(r)
      i.network.address.to_s + "/" + i.network.prefix.to_s
    else
      r
    end
  end
  return result.sort.uniq
end

# generate resolver
resolver = Dnsruby::DNS.open

# collect results, format as Postfix CIDR style map
spf_results = domains.collect{|d| get_spf_results(d, resolver)}.flatten.uniq.sort

# compare number of results
ratio = (old_lines.to_f / spf_results.count.to_f)
if (ratio < 0.9 or ratio > 1.1) and old_lines > 0
  puts "WARNING: More than 10% difference in number of results detected, old: #{old_lines}, new: #{spf_results.count}"
  puts "Call with -f to force writing (this error message will be displayed anyways)"
  unless params.has_key?("f") and params["f"]
    exit 1
  end
end

# write file
File.write(outfile, spf_results.join(" permit\n") + " permit\n")
