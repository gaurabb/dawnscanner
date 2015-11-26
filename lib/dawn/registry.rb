module Dawn
  class Registry
    include DataMapper::Resource
    property :id, Serial

    property :target,           String
    property :registry_version, String, :default=>"0.5"
    property :dawn_version,     String, :default=>Dawn::VERSION
    property :output_dir,       String, :length=>255
    property :scan_started,     DateTime
    property :scan_duration,    Float
    property :scan_status,      Enum[ :completed, :failed ], :default=>:failed
    property :issues_found,     Integer


    property :created_at, DateTime
    property :created_on, Date
    property :updated_at, DateTime
    property :updated_on, Date


    def do_save(options={})

      self.target         = options[:target]
      self.output_dir     = options[:output_dir]
      self.scan_status    = options[:scan_status]
      self.issues_found   = options[:issues_found]
      self.scan_started   = options[:scan_started]
      self.scan_duration  = options[:scan_duration]

      save
    end
  end
end

# DataMapper.setup(:default, "sqlite3://#{Dawn::Core.registry_db_name}")
