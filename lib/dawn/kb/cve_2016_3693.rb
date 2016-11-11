module Dawn
		module Kb
			# Automatically created with rake on 2016-11-11
			class CVE_2016_3693
				include DependencyCheck

				def initialize
					title   = "safemode information leakage"
					message = "The Safemode gem before 1.2.4 for Ruby, when initialized with a delegate object that is a Rails controller, allows context-dependent attackers to obtain sensitive information via the inspect method."
          super({
            :title=>title,
            :name=> "CVE-2016-3693",
            :cve=>"2016-3693",
            :cvss=>"AV:N/AC:M/Au:N/C:P/I:P/A:P",
            :release_date => Date.new(2016, 5, 20),
            :cwe=>"200",
            :owasp=>"",
            :applies=>["rails", "sinatra", "padrino"],
            :kind=>Dawn::KnowledgeBase::DEPENDENCY_CHECK,
            :message=>message,
            :mitigation=>"Upgrade safemode gem to newest version",
            :aux_links=>['http://www.openwall.com/lists/oss-security/2016/04/20/8']
          })
          self.safe_dependencies = [{:name=>"safemode", :version=>['1.2.5']}]
				end
			end
		end
end
