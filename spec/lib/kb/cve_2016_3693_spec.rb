require 'spec_helper'
describe "The CVE-2016-3693 vulnerability" do
	before(:all) do
		@check = Dawn::Kb::CVE_2016_3693.new
		# @check.debug = true
	end
	it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"safemode", :version=>"1.2.4"}]
		expect(@check.vuln?).to   eq(true)
	end
	it "is not reported when a fixed release is detected" do
    @check.dependencies = [{:name=>"safemode", :version=>"1.2.5"}]
		expect(@check.vuln?).to   eq(false)
	end
end
