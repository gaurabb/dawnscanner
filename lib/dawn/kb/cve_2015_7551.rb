module Dawn
  module Kb
    # Automatically created with rake on 2016-11-11
    class CVE_2015_7551
      include RubyVersionCheck

      def initialize
        title   = "Arbitrary code execution in Fiddle::Handle implementation"
        message = "The Fiddle::Handle implementation in ext/fiddle/handle.c in Ruby before 2.0.0-p648, 2.1 before 2.1.8, and 2.2 before 2.2.4, mishandles tainting, which allows context-dependent attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted string, related to the DL module and the libffi library. NOTE: this vulnerability exists because of a CVE-2009-5147 regression."
        super({
          :title=>title,
          :name=> "CVE-2015-7551",
          :cve=>"2015-7551",
          :cvss=>"AV:L/AC:L/Au:N/C:P/I:P/A:P",
          :release_date => Date.new(2016, 3, 23),
          :cwe=>"",
          :owasp=>"",
          :applies=>["rails", "sinatra", "padrino"],
          :kind=>Dawn::KnowledgeBase::DEPENDENCY_CHECK,
          :message=>message,
          :mitigation=>"Upgrade ruby interpreter version to 2.0,0-p648, 2.1.8, 2.2.4 or later",
          :aux_links=>['http://www.oracle.com/technetwork/topics/security/bulletinapr2016-2952098.html', 'https://www.ruby-lang.org/en/news/2015/12/16/unsafe-tainted-string-usage-in-fiddle-and-dl-cve-2015-7551/']
        })
        self.safe_rubies = [{:engine=>"ruby", :version=>"2.0.0", :patchlevel=>"p648"},
                            {:engine=>"ruby", :version=>"2.1.8", :patchlevel=>""},
                            {:engine=>"ruby", :version=>"2.2.4", :patchlevel=>""}
        ]

      end
    end
  end
end
