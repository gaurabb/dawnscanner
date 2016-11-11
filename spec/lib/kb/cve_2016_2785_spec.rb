require 'spec_helper'
describe "The CVE-2016-2785 vulnerability" do
  before(:all) do
    @check = Dawn::Kb::CVE_2016_2785.new
    # @check.debug = true
  end
  it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"puppet", :version=>"4.4.1"}]
    expect(@check.vuln?).to   eq(true)
  end
  it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"puppet", :version=>"4.3.1"}]
    expect(@check.vuln?).to   eq(true)
  end

  it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"puppet", :version=>"4.2.1"}]
    expect(@check.vuln?).to   eq(true)
  end

  it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"puppet", :version=>"4.1.0"}]
    expect(@check.vuln?).to   eq(true)
  end

  it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"puppet", :version=>"4.0.0"}]
    expect(@check.vuln?).to   eq(true)
  end


  it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"puppet_server", :version=>"2.3.1"}]
    expect(@check.vuln?).to   eq(true)
  end

  it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"puppet_server", :version=>"2.3.1"}]
    expect(@check.vuln?).to   eq(true)
  end

  it "is reported when the vulnerable gem is detected" do
    @check.dependencies = [{:name=>"puppet_agent", :version=>"1.4.1"}]
    expect(@check.vuln?).to   eq(true)
  end


  it "is not reported when a fixed release is detected" do
    @check.dependencies = [{:name=>"puppet", :version=>"4.4.2"}]
    expect(@check.vuln?).to   eq(false)
  end

  it "is not reported when a fixed release is detected" do
    @check.dependencies = [{:name=>"puppet_server", :version=>"2.3.2"}]
    expect(@check.vuln?).to   eq(false)
  end

  it "is not reported when a fixed release is detected" do
    @check.dependencies = [{:name=>"puppet_agent", :version=>"1.4.2"}]
    expect(@check.vuln?).to   eq(false)
  end

end
