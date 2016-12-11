require 'spec_helper'
describe "The CVE-2015-3900 vulnerability" do
		before(:all) do
				@check = Dawn::Kb::CVE_2015_3900.new
				# @check.debug = true
		end

		it "is reported when the vulnerable rubygem is detected" do
				@check.my_gem_version="2.0.15"
				expect(@check.vuln?).to   eq(true)
		end
		it "is reported when the vulnerable rubygem is detected" do
				@check.my_gem_version="2.2.3"
				expect(@check.vuln?).to   eq(true)
		end
		it "is reported when the vulnerable rubygem is detected" do
				@check.my_gem_version="2.4.6"
				expect(@check.vuln?).to   eq(true)
		end

		it "is not reported when the safe rubygem is detected" do
				@check.my_gem_version="2.0.16"
				expect(@check.vuln?).to   eq(false)
		end
		it "is not reported when the safe rubygem is detected" do
				@check.my_gem_version="2.2.4"
				expect(@check.vuln?).to   eq(false)
		end
		it "is not reported when the safe rubygem is detected" do
				@check.my_gem_version="2.4.7"
				expect(@check.vuln?).to   eq(false)
		end

end
