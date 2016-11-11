require 'spec_helper'
describe "The CVE-2015-7551 vulnerability" do
  before(:all) do
    @check = Dawn::Kb::CVE_2015_7551.new
    # @check.debug = true
  end
  it "is reported when the vulnerable gem is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.2.3", :patchlevel=>"p923"}
    expect(@check.vuln?).to   eq(true)
  end

  it "is reported when the vulnerable gem is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.2.2", :patchlevel=>"p123"}
    expect(@check.vuln?).to   eq(true)
  end

  it "is reported when the vulnerable gem is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.1.7", :patchlevel=>"p232"}
    expect(@check.vuln?).to   eq(true)
  end

  it "is reported when the vulnerable gem is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.1.2", :patchlevel=>"p221"}
    expect(@check.vuln?).to   eq(true)
  end


  it "is reported when the vulnerable gem is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.0.0", :patchlevel=>"p647"}
    expect(@check.vuln?).to   eq(true)
  end

  it "is not reported when a fixed release is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.2.4", :patchlevel=>"p0"}
    expect(@check.vuln?).to   eq(false)
  end
  it "is not reported when a fixed release is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.2.4", :patchlevel=>"p100"}
    expect(@check.vuln?).to   eq(false)
  end

  it "is not reported when a fixed release is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.1.8", :patchlevel=>"p912"}
    expect(@check.vuln?).to   eq(false)
  end
  it "is not reported when a fixed release is detected" do
    @check.detected_ruby ={:engine=>"ruby", :version=>"2.0.0", :patchlevel=>"p648"}
    expect(@check.vuln?).to   eq(false)
  end

end
