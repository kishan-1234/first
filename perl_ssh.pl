use strict;
use warnings;
use Expect;
#use NET::SSH::Expect;

my $log = "perlssh.log";
my $ip = "10.102.56.220";
my $user = "root";
my $password = "freebsd";
my $time = 10;

my $exp = Expect->new();
$exp = Expect->spawn("ssh -oStrictHostKeyChecking=no $user\@$ip");
#my $match = $exp->expect($time,-re,"ogin:");

$exp->autoflush(1);

my $match = $exp->expect($time,'-re',"assword:");
my $out;

#print $match;
if(!$match)
{
	print "Unable to reach to device $ip";
}
else
{
	print $exp "$password\r";
	my $match=$exp->expect($time,'-re',"#");
	if(!$match)
	{
		print "does not reach  prompt";
	}
	else
	{	
		#print "HI";
		#print $exp "$password\r";
                # intially print $exp "xl console 111\r\r\r";
		print $exp "xl console 111\r";
	        #print $exp "\r\r\r";
                #print $exp "\n\n\n\n";
                #print $exp "\n\n\n\n";
		print $exp "\r";
		my $match=$exp->expect($time,'-re',"^>",'-re',"ogin:");
		if(!$match)
		{
			print "Not able to run commands";
		}
		else
		{
              #$exp->clear_accum();	
			if($match eq 2)
		{
			print $exp "nsroot\r";
			$match=$exp->expect($time,'-re','assword:');
			if(!$match)
			{
				print "Error in sending password";
			}
			else
			{
				print $exp "nsroot\r";
			}
		}
            #$exp->clear_accum();
			print $exp "sh license\r";
			if(!($exp->expect($time,'-re','^>')))
			{	
				print "not able to run command";
			}
			else
			{
			$out = $exp->exp_before();
			print $out;
			print $exp "exit\r";
			if(!($exp->expect($time,'-re','ogin:')))
			{
				print "Not exiting";
			}
			else
			{
				$exp->send("\c]");
				$exp->close();
			}
			}
		}
	}
}
