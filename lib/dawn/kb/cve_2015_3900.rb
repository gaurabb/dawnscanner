module Dawn
	module Kb
		# Automatically created with rake on 2016-12-10
		class CVE_2015_3900
			include GemCheck

			def initialize
				title = "RubyGems DNS hijack attack"
				message = "RubyGems 2.0.x before 2.0.16, 2.2.x before 2.2.4, and 2.4.x before 2.4.7 does not validate the hostname when fetching gems or making API requests, which allows remote attackers to redirect requests to arbitrary domains via a crafted DNS SRV record, aka a \"DNS hijack attack.\""
			 super({
            :title=>title,
            :name=> "CVE-2015-3900",
            :cve=>"2015-3900",
            :osvdb=>"",
            :cvss=>"AV:N/AC:L/Au:N/C:N/I:P/A:N",
            :release_date => Date.new(2015, 6, 24),
            :cwe=>"254",
            :owasp=>"A9",
            :applies=>["rails", "sinatra", "padrino"],
            :kind=>Dawn::KnowledgeBase::GEM_CHECK,
            :message=>message,
            :mitigation=>"Please upgrade rubygem to version 2.0.16, 2.2.4, 2.4.7 or later.",
            :aux_links=>[""]
           })

          self.safe_versions = [{:version=>['2.0.16', '2.2.4', '2.4.7']}]
			end
		end
	end
end
