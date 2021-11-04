TE=`date +%Y-%m-%d`
touch /aaa
touch /ptxt
touch /ntxt
cpu=`top -b -n1 | grep -Po '[0-9.]+ id' | awk '{print 100-$1}'` ;
TOTAL=`free | grep Mem | awk '{print $2}'`
USED=`free | grep Mem | awk '{print $3}'`
use=`expr 100 \* $USED / $TOTAL`
echo -e "=====================================\n" >> /ptxt
echo -e "$DATE 보안 취약점 점검 내용입니다.\n" >> /ptxt
echo -e "현재 CPU 사용률 : $cpu%\n" >> /ptxt
echo -e "현재 메모리 사용률 : $use%\n" >> /ptxt
echo "===============[양호]=================" >> /ptxt
echo "===============[취약]=================" >> /ntxt


str=`grep "#PermitRootLogin" /etc/ssh/sshd_config`
if [ "$str" ]; then
	echo "[U-01] root 계정 원격 접속 제한" >> /ntxt			
else
	echo "[U-01] root 계정 원격 접속 제한" >> /ptxt
	
fi



str=`cat /etc/pam.d/system-auth | grep dcredit=-1 | grep ucredit=-1 | grep lcredit=-1 | grep ocredit=-1 | grep minlen=8 | grep enforce_for_root`
	
if [ "$str" ]; then
	echo "[U-02]패스워드 복잡성 설정" >> /ptxt
		

else
	echo "[U-02]패스워드 복잡성 설정" >> /ntxt

fi

limit1=`grep deny= /etc/pam.d/password-auth | awk -F deny= '{print $2}' | awk '{print $1}'`
limit2=`grep deny= /etc/pam.d/system-auth | awk -F deny= '{print $2}' | awk '{print $1}'`

if [ $limit1 -ge 5 ] && [  $limit2 -ge 5 ]; then
	echo "[U-03]계정 잠금 임계값 설정" >> /ptxt

else
	echo "[U-03]계정 잠금 임계값 설정" >> /ntxt

fi



term=`awk '/PASS_MAX/ {print $2}' /etc/login.defs | grep -v PASS`

        if [ $term -le 90 ]; then
		echo "[U-04] 패스워드 최대 사용 기간 설정" >> /ptxt
            

        else
		echo "[U-04] 패스워드 최대 사용 기간 설정" >> /ntxt
	fi


term=`awk '/PASS_MAX/ {print $2}' /etc/login.defs | grep -v PASS`
str=`awk -F: '{print $2}' /etc/passwd | grep -v x`
if [ -e $(ls /etc/shadow) ] && [ -z $str ]; then
	echo "[U-05]패스워드 파일 보호" >> /ptxt
else
	echo "[U-05]패스워드 파일 보호" >> /ntxt
fi
		


root_path1=`grep PATH= /root/.bash_profile | awk -F. '{print $2}'`
root_path2=`grep PATH= /root/.bash_profile | awk -F: '{print $2}'`

if [ -z $root_path1 ] && [ $root_path2 != "\$PATH"  ]; then
	echo "[U-06] root 홈, 패스 디렉터리 권한 및 패스 설정" >> /ptxt

else
	echo "[U-06] root 홈, 패스 디렉터리 권한 및 패스 설정" >> /ntxt

fi 



nouser_file=`find / -nouser -o -nogroup 2>/dev/null`
num=`echo "$str" | wc -l`

if [ -z "$nouser_file" ]; then
	echo "[U-07] 파일 및 디렉터리 소유자 설정" >> /ptxt

else
	echo "[U-07] 파일 및 디렉터리 소유자 설정" >> /ntxt

fi


file_own=`ls -l /etc/passwd | grep -v root`
group_per=`ls -l /etc/passwd | cut -d r -f 3 | grep [a-z]`
other_per=`ls -l /etc/passwd | cut -d r -f 4 | grep [a-z]`

if [ -z "$group_per" ] && [ -z "$other_per" ] && [ -z "$file_own" ]; then
	echo "[U-08] /etc/passwd 파일 소유자 및 권한 설정" >> /ptxt

else
	echo "[U-08] /etc/passwd 파일 소유자 및 권한 설정" >> /ntxt
fi


file_own=`ls -l /etc/shadow | grep -v root`
file_per=`ls -l /etc/shadow | cut -d" " -f1 | grep [w,x]`
if [ -z "$file_per" ] && [ -z "$file_own" ]; then
		echo "[U-09]/etc//shadow 파일 소유자 및 권한 설정" >> /ptxt

        else
		echo "[U-09]/etc//shadow 파일 소유자 및 권한 설정" >> /ntxt

fi

file_own=`ls -l /etc/hosts | grep -v root`
group_per=`ls -l /etc/hosts | cut -d" " -f1 | cut -d"r" -f3 | grep [w,x]`
other_per=`ls -l /etc/hosts | cut -d" " -f1 | cut -d"r" -f4 | grep [w,x]`


if [ -z "$file_own" ] && [ -z "$group_per" ] && [ -z "$other_per" ]; then
	echo "[U-10] /etc/shadow 파일 소유자 및 권한 설정" >> /ptxt
   

else
	echo "[U-10] /etc/shadow 파일 소유자 및 권한 설정" >> /ntxt
fi 



if [ -z $(rpm -qa | grep xinetd*) ]; then
	echo "[U-11]/etc/(x)inetd.conf 파일 소유자 및 권한 설정 " >> /ptxt

else
	if [ -z "$file_own" ] && [ -z "$group_per" ] && [ -z "$other_per" ]; then
		echo "[U-11]/etc/(x)inetd.conf 파일 소유자 및 권한 설정 " >> /ptxt

        else
		echo "[U-11]/etc/(x)inetd.conf 파일 소유자 및 권한 설정 " >> /ntxt
	fi
fi



file_own=`ls -l /etc/rsyslog.conf | grep -v root`
group_per=`ls -l /etc/rsyslog.conf | cut -d" " -f1 | cut -d"r" -f3 | grep [w,x]`
other_per=`ls -l /etc/rsyslog.conf | cut -d" " -f1 | cut -d"r" -f4 | grep [w,x]`

if [ -z "$file_own" ] && [ -z "$group_per" ] && [ -z "$other_per" ]; then
	echo "[U-12]/etc/rsyslog.conf파일 소유자 및 권한 설정" >> /ptxt

else	
	echo "[U-12]/etc/rsyslog.conf파일 소유자 및 권한 설정" >> /ntxt
fi


file_own=`ls -l /etc/services | grep -v root`
group_per=`ls -l /etc/services | cut -d" " -f1 | cut -d"r" -f3 | grep [w,x]`
other_per=`ls -l /etc/services | cut -d" " -f1 | cut -d"r" -f4 | grep [w,x]`

if [ -z "$file_own" ] && [ -z "$group_per" ] && [ -z "$other_per" ]; then

	echo "[U-13]/etc/services 파일 소유자 및 권한 설정 " >> /ptxt

else

	echo "[U-13]/etc/services 파일 소유자 및 권한 설정 " >> /ntxt
fi


str=`ls -l /home | cut -d" " -f1 | cut -dx -f2 | grep w`

if [ -z "$str" ]; then
	echo "[U-15] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정" >> /ptxt

else
	echo "[U-15] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정" >> /ntxt
fi


equiv=`find /etc -name hosts.equiv -exec ls -l {} \;`
rhosts=`find $HOME -name .rhosts -exec ls -l {} \;`
echo=$equiv


if [ -z "$equiv" ] && [ -z "$rhosts" ]; then
	echo "[U-17] $HOME/.rhosts, hosts.equiv 사용 금지" >> /ptxt  

else
	file_own1=`ls -l /etc/hosts.equiv | grep -v root`
	file_own2=`ls -l $HOME/.rhosts | grep -v root`
        equiv_per=`ls -l /etc/hosts.equiv | cut -d" " -f1 | grep x`
        rhosts_per=`ls -l $HOME/.rhosts | cut -d" " -f1 | grep x`


        if [ -z "$file_own1" ] && [ -z "$file_own2" ] && [ -z "$equiv_per" ] && [ -z "$rhosts_per" ]; then
		echo "[U-17] $HOME/.rhosts, hosts.equiv 사용 금지" >> /ptxt                        
	else
                echo "[U-17] $HOME/.rhosts, hosts.equiv 사용 금지" >> /ntxt
	fi
fi


deny=`cat /etc/hosts.deny | grep -w "^ALL" | grep -w "ALL$"`
allow=`cat /etc/hosts.allow | grep -w "^ALL" | grep -w "ALL$"`

if [ "$deny" ] && [ -z "$allow" ]; then
	echo "[U-18] 접속 IP 및 포트 제한" >> /ptxt
  

else
        echo "[U-18] 접속 IP 및 포트 제한" >> /ntxt

fi



file_own1=`ls -l /etc/cron.deny | grep -v root`
file_own2=`ls -l /etc/cron.allow | grep -v root`
deny_per=`find /etc -name cron.deny -perm -641`
allow_per=`find /etc -name cron.allow -perm -641`

if [ -z "$file_own1" ] && [ -z "$file_own2" ] && [ -z "$deny_per" ] && [ -z "$allow_per" ]; then
	echo "[U-19] cron 파일 소유자 및 권한 설정" >> /ptxt
               

else
	echo "[U-19] cron 파일 소유자 및 권한 설정" >> /ntxt

fi 



str=`rpm -qa | grep finger`

if [ -z "$str" ]; then
	echo "[U-20] Finger 서비스 비활성화" >> /ptxt


else
	echo "[U-20] Finger 서비스 비활성화" >> /ntxt

fi


str=`rpm -qa | grep ftp`
allow_per=`find /etc -name cron.allow -perm -641`

if [ -z "$str" ]; then
	echo "[U-21] Anonymous FTP 비활성화" >> /ptxt

else
	anon=`cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable= | cut -d= -f2`
        if [ $anon != YES ] && [ $anon != yes ]; then
        	echo "[U-21] Anonymous FTP 비활성화" >> /ptxt

        else
                echo "[U-21] Anonymous FTP 비활성화" >> /ntxt
	fi
fi


str=`rpm -qa | grep -e "rsh" -e "rlogin" -e "rexec"`	
rsh=`systemctl status rsh.socket | grep -w listening`
rlogin=`systemctl status rlogin.socket | grep -w listening`
rexec=`systemctl status rexec.socket | grep -w listening`

if [ -z "$str" ]; then
	echo "[U-22]r 계열 서비스 비활성화" >> /ptxt

else

        if [ -z "$rsh" ] && [ -z "$rlogin" ] && [ -z "$rexec" ]; then
        	echo "[U-22]r 계열 서비스 비활성화" >> /ptxt

        else
       		echo "[U-22]r 계열 서비스 비활성화" >> /ntxt
	fi
fi




str=`rpm -qa | grep xinetd`
str2=`cat /etc/xinetd.d/echo* /etc/xinetd.d/daytime* /etc/xinetd.d/discard* /etc/xinetd.d/chargen* | grep disable | grep no`

if [ -z "$str" ]; then
	echo "[U-23]DoS 공격에 취약한 서비스 비활성화" >> /ptxt

else

	if [ -z "$str2" ]; then
		echo "[U-23]DoS 공격에 취약한 서비스 비활성화" >> /ptxt
                
	else
		echo "[U-23]DoS 공격에 취약한 서비스 비활성화" >> /ntxt

	fi
fi


str=`ps -ef | grep nfs | grep -v grep`

if [ -z "$str" ]; then
	echo "[U-24] NFS서비스 비활성화" >> /ptxt

else
        echo "[U-24] NFS서비스 비활성화" >> /ntxt

fi



                
str=`cat /etc/exports | grep "*"`

if [ -z "$str" ]; then
	echo "[U-25] NFS 접근 통제 " >> /ptxt

else
        echo "[U-25] NFS 접근 통제 " >> /ntxt
fi




str=`ps -ef | grep automount | grep -v grep`
if [ -z "$str" ]; then
	echo "[U-26]automountd 제거 " >> /ptxt

else
        echo "[U-26]automountd 제거 " >> /ptxt

fi





str=`rpm -qa | grep xinetd`

if [ -z "$str" ]; then
	echo "[U-27]RPC 서비스 확인 " >> /ptxt

else
        	
	str2=`cat /etc/xinetd.d/rpc* /etc/xinetd.d/rusersd* /etc/xinetd.d/walld* /etc/xinetd.d/sprayd* /etc/xinetd.d/rstatd* /etc/xinetd.d/rexd* /etc/xinetd.d/kcms_server* /etc/xinetd.d/cachefsd* | grep disable | grep no`

        if [ -z "$str2" ]; then
        	echo "[U-27]RPC 서비스 확인 " >> /ptxt

        else
                echo "[U-27]RPC 서비스 확인 " >> /ntxt
	fi
fi



str=`ps -ef | grep -e "ypserv" -e "ypxfrd" -e "ypbind" -e "yppasswdd" -e "ypupdated" | grep -v grep`

if [ -z "$str" ]; then
	echo "[U-28]NIS, NIS+ 점검 " >> /ptxt

else
	echo "[U-28]NIS, NIS+ 점검 " >> /ntxt
fi


	

if [ -z $(rpm -qa | grep xinetd*) ]; then
	echo "[U-29]tftp, talk 서비스 비활성화 " >> /ptxt

else
	tftp=`pgrep tftp`
	talk=`pgrep talk`
	ntalk=`pgrep ntalk`

        if [ -z "$tftp" ] && [ -z "$talk" ] && [ -z "$ntalk" ]; then
        	echo "[U-29]tftp, talk 서비스 비활성화 " >> /ptxt

        else
        	echo "[U-29]tftp, talk 서비스 비활성화 " >> /ntxt
	fi
fi



str=`ps -ef | grep sendmail | grep -v grep`
if [ -z "$str" ]; then
	echo "[U-30]Sendmail 버전 점검" >> /ptxt

else

         echo "[U-30]Sendmail 버전 점검" >> /ntxt
fi


str=`ps -ef | grep sendmail | grep -v grep`

if [ -z "$str" ]; then
	echo "[U-31]스팸 메일 릴레이 제한" >> /ptxt

else
	str2=`cat /etc/mail/sendmail.cf | grep "#R$\*" | grep Relaying`

        if [ -z "$str2" ]; then
        	echo "[U-31]스팸 메일 릴레이 제한" >> /ptxt

        else
                echo "[U-31]스팸 메일 릴레이 제한" >> /ntxt
	fi
fi



str=`ps -ef | grep sendmail | grep -v grep`
if [ -z "$str" ]; then
	echo "[U-32]일반 사용자의 Sendmail 실행 방지" >> /ptxt

else

        str2=`cat /etc/mail/sendmail.cf | grep PrivacyOptions | grep restrictqrun`
	if [ "$str2" ]; then
		echo "[U-32]일반 사용자의 Sendmail 실행 방지" >> /ptxt
                        

        else
               echo "[U-32]일반 사용자의 Sendmail 실행 방지" >> /ntxt
	fi
fi


str=`ps -ef | grep named | grep -v grep`

if [ -z "$str" ]; then
	echo "[U-33]DNS 보안 버전 패치" >> /ptxt

else
        echo "[U-33]DNS 보안 버전 패치" >> /ntxt
fi



str=`ps -ef | grep named | grep -v grep`

if [ -z "$str" ]; then
	echo "[U-34]DNS 보안 버전 패치" >> /ptxt
	

else

	str2=`cat /etc/named.conf | grep allow-transfer`
	str3=`echo $str2 | grep any`

        if [ "$str2" ] && [ -z "$str3"  ]; then
		echo "[U-34]DNS 보안 버전 패치" >> /ptxt         

        else
		echo "[U-34]DNS 보안 버전 패치" >> /ntxt 

	fi
fi


cat /ptxt /ntxt > /aaa
python3 /home/itbank/python.py
rm -rf /ptxt /ntxt /aaa
