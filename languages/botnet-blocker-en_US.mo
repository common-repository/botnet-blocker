��          �   %   �      `  T   a  �   �  �   H  �     �     	   �     �     �     �     �     �  D   �     0  �   K     �  	   �  	   �  <   �  	   *     4     9     ?     D     J     R     [  }  h  -  �  j  
  �     �   =  �   :  	   �     �     �     �            D   "     g  �   �       	     	     <   $  	   a     k     p     v     {     �     �     �                                           	          
                                                                       A list of DNS names to always mark as a bot (unless also present on the white list). A list of DNS names to never mark as a bot.  The whitelist overrides the black lists - if the same name is in both lists then it will be allowed. A list of IP addresses and/or network/mask combinations to always mark as a bot (unless also present on the white list).  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ). A list of IP addresses and/or network/mask combinations to never mark as a bot.  The whitelist overrides the black list - if the same address is in both lists then it will be allowed.  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ). A list of IP addresses and/or network/mask combinations to skip checking.  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ). Blacklist Botnet Blocker Botnet Blocker Settings Choose File DNS Blacklist DNS Whitelist If checked, the local server address will be added to the skip list. Realtime Blacklist Service Redirects detected bots to a 404 page on page load.  Make sure your IP address is in the whitelist before activating (just in case)! Settings Skip List Skip Self Which RBL service to use when checking for botnet addresses. Whitelist dsbl njabl ordb sorbs spamcop spamhaus spamhaus_xbl Project-Id-Version: Botnet Blocker
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2015-09-15 21:36-0500
PO-Revision-Date: 2015-09-29 15:19-0600
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Last-Translator: Dennis Wallace <dwallace@shr.global>
Language-Team: 
X-Generator: Poedit 1.8.1
Plural-Forms: nplurals=2; plural=(n != 1);
Language: en
 A list of DNS names to always mark as a bot (unless also present on the white list). This is either a Regular Expression bounded by slashes ( /expression/ ), or will be matched to the right-most end of the DNS name (e.g., .amazonaws.com will match ec2-some-ip-here.region-name.compute.amazonaws.com ). A list of DNS names to never mark as a bot.  This is either a Regular Expression bounded by slashes ( /expression/ ), or will be matched to the right-most end of the DNS name (e.g., .amazonaws.com will match ec2-some-ip-here.region-name.compute.amazonaws.com ). The whitelist overrides the black lists - if the same name is in both lists then it will be allowed. A list of IP addresses and/or network/mask combinations to always mark as a bot (unless also present on the white list).  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ). A list of IP addresses and/or network/mask combinations to never mark as a bot.  The whitelist overrides the black list - if the same address is in both lists then it will be allowed.  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ). A list of IP addresses and/or network/mask combinations to skip checking.  Network/mask entries must be in CIDR form ( e.g., 192.168.0.0/16 ). Blacklist Botnet Blocker Botnet Blocker Settings Choose File DNS Blacklist DNS Whitelist If checked, the local server address will be added to the skip list. Realtime Blacklist Service Redirects detected bots to a 404 page on page load.  Make sure your IP address is in the whitelist before activating (just in case)! Settings Skip List Skip Self Which RBL service to use when checking for botnet addresses. Whitelist DSBL NJABL ORDB SORBS Spamcop Spamhaus Zen list Spamhaus XBL List 