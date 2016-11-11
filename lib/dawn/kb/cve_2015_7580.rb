module Dawn
  module Kb
    # Automatically created with rake on 2016-11-11
    class CVE_2015_7580
      include DependencyCheck

      def initialize
        title   = "Cross site scripting in rails-html-sanitizer gem"
        message = "Cross-site scripting (XSS) vulnerability in lib/rails/html/scrubbers.rb in the rails-html-sanitizer gem before 1.0.3 for Ruby on Rails 4.2.x and 5.x allows remote attackers to inject arbitrary web script or HTML via a crafted CDATA node."
        super({
          :title=>title,
          :name=> "CVE-2015-7580",
          :cve=>"2015-7580",
          :cvss=>"AV:N/AC:M/Au:N/C:N/I:P/A:N",
          :release_date => Date.new(2016, 2, 15),
          :cwe=>"79",
          :owasp=>"A3",
          :applies=>["rails"],
          :kind=>Dawn::KnowledgeBase::DEPENDENCY_CHECK,
          :message=>message,
          :mitigation=>"Upgrade rails-html-sanitizer or the whole rails stack to the latest available version",
          :aux_links=>['https://github.com/rails/rails-html-sanitizer/commit/63903b0eaa6d2a4e1c91bc86008256c4c8335e78']
        })
        self.safe_dependencies = [{:name=>"rails-html-sanitizer", :version=>['1.0.3']}]

      end
    end
  end
end
