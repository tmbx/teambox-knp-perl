$default_port = 8081;

our %config =
  (
   kps_host => 'localhost',
   kps_port => $default_port,

   ots_host => 'localhost',
   ots_port => $default_port,

   ous_host => 'localhost',
   ous_port => $default_port,

   ops_host => 'localhost',
   ops_port => $default_port,

   iks_host => 'localhost',
   iks_port => $default_port,

   eks_host => 'localhost',
   eks_port => $default_port,

   # Address and member ID of the source Teambox member.
   source_username => 'source',
   source_password => 'source',
   source_name => 'Mister Source',
   source_mid => 10,
   source_address => 'source@source.com',
   source_ex => '/ex=/o=Opersys AD/ou=First Administrative Group/cn=Recipients/cn=source',

   # Address and member ID of the target Teambox member.
   target_username => 'target',
   target_password => 'target',
   target_name => 'Miss Target',
   target_mid => 11,
   target_address => 'target@target.com',
   target_ex => '/ex=/o=Opersys AD/ou=First Administrative Group/cn=Recipients/cn=target',

   # Address and member ID that don't have the Teambox service.
   invalid_name => 'Sir Invalid Name',
   invalid_mid => 999,
   invalid_address => 'somebody@someplace.com',

   # Address of somebody receiving messages encrypted with passwords.
   other1_password => 'blarg',
   other1_name => 'Signor Other Person',
   other1_address => 'neumann@lostwebsite.net',

   # Another one.
   other2_password => 'blorg',
   other2_name => 'Signor Somebody',
   other2_address => 'fdgonthier@lostwebsite.net'
  );

