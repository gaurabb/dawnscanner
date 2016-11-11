module Dawn
  module Kb
    # Automatically created with rake on 2016-11-11
    class CVE_2016_2785
      include DependencyCheck

      def initialize
        title   = "Puppet authentication access restriction bypass"
        message = "Puppet Server before 2.3.2 and Ruby puppetmaster in Puppet 4.x before 4.4.2 and in Puppet Agent before 1.4.2 might allow remote attackers to bypass intended auth.conf access restrictions by leveraging incorrect URL decoding."

        super({
          :title=>title,
          :name=> "CVE-2016-2785",
          :cve=>"2016-2785",
          :cvss=>"AV:N/AC:L/Au:N/C:P/I:P/A:P",
          :release_date => Date.new(2016, 6, 10),
          :cwe=>"284",
          :owasp=>"",
          :applies=>["rails", "sinatra", "padrino"],
          :kind=>Dawn::KnowledgeBase::DEPENDENCY_CHECK,
          :message=>message,
          :mitigation=>"Upgrade puppet, puppet_server and puppet_agent gems to latest version available.",
          :aux_links=>['']
        })
        self.safe_dependencies = [{:name=>"puppet", :version=>['4.4.2']}, {:name=>"puppet_server", :version=>['2.3.2']}, {:name=>"puppet_agent", :version=>['1.4.2']}]

      end
    end
  end
end
