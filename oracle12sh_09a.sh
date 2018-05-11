#!/bin/bash

# referencias:
#
#
#
# 
# https://lalitkumarb.wordpress.com/2014/10/01/mandatory-steps-for-12c-installation/
# https://www.cvedetails.com/cve/CVE-2016-0499/
# https://docs.oracle.com/cd/B28359_01/server.111/b28320/initparams215.htm#REFRN10275
# http://arup.blogspot.mx/2008/08/why-should-you-set-adminrestrictionslis.html 
# https://docs.oracle.com/cd/B10501_01/network.920/a96581/listener.htm#500821
#
#
# Este script valida:
#
#
#
## demon@scitum GIT Control version 0.9a ts=8, mn=obstacle


# common routines
#


version="0.9a"



write_output()
{

  module=$1
  ok=$2

  if [ $ok = "OK" ]; then
    echo "$module, Cumple" >> $nombre_archivo
  else
    echo "$module, No Cumple" >> $nombre_archivo
  fi
}


info_message()
{
  message=$1
  CYAN='\033[0;36m'
  NC='\033[0m' # No Color
  echo -e "${CYAN}INFO:${NC} $message"
}

error_message()
{
  message=$1
  RED='\033[0;31m'
  NC='\033[0m' # No Color
  echo -e "${RED}ERROR:${NC} $message"
  write_output "$message" "ERROR"
}

warning_message()
{
  message=$1
  ORANGE='\033[0;33m'
  NC='\033[0m' # No Color
  echo -e "${ORANGE}WARNING:${NC} $message"
}

ok_message()
{
  message=$1
  GREEN='\033[0;32m'
  NC='\033[0m' # No Color
  echo -e "${GREEN}OK:${NC} $message"
  write_output "$message" "OK"
}

version() { echo "$@" | gawk -F. '{ printf("%03d%03d%03d\n", $1,$2,$3); }'; }

process_owner()
{
  process_name=$1
  # tomamos el mismo found, si cambiamos la rutina hay que modificarca aca tambien.
  # regexp ?

  owner=`ps -ef | grep "$process_name" | grep -v grep | awk '{ print $1 }'`

  echo "$owner"
}
 

bye()
{
  info_message "Se detiene la ejeccion del script"
  echo
  exit 250
}


process_running()
{
  process_name=$1

  found=`ps -ef | grep "$process_name" | grep -v grep | wc -l`
  if [ $found -gt 0 ]; then
    return_val=1
  else
    return_val=0
  fi

  echo "$return_val"
}


search_file()
{
  file_to_search="$1"
  key_to_search="$2"
  found=0

  # existe el archivo

  if [ -f "$file_to_search" ]; then
    count=`cat $file_to_search | grep -e "$key_to_search" | wc -l`
    if [ $count -gt 0 ]; then 
      found=1
    fi
  else
    error_message "no puedo abrir el archivo $file_to_search"
  fi

  echo "$found"
}

interfaces_to_array()
{

  # put interfaces into array, ignore 127.0.0.1
  counter=0
  # cleanup array
  INTERFACES_ARRAY=""
  int_composer=""

  if [ -x /usr/sbin/ifconfig ]; then
    ifconfig_path="/usr/sbin/ifconfig"
    grab_interfaces_cmd="$ifconfig_path -a | grep inet | grep -v inet6 | grep -v 127.0.0.1 | awk '{ print \$2 }'"
  else
    if [ -x /usr/sbin/ip ]; then
      # lets use ip
      ip_path="/usr/sbin/ip"
      grab_interfaces_cmd="$ip_path addr list | grep inet | grep -v inet6 | grep -v 127.0.0.1 | awk '{ print \$2 }' | cut -d\"/\" -f1"
    else
      error_message "No se puede localizar /usr/sbin/ifconfig ni /usr/sbin/ip"
      bye
    fi
  fi


  for x in `eval $grab_interfaces_cmd`
  do
    INTERFACES_ARRAY[$counter]=$x
    counter=`expr $counter + 1`
    if [ $counter -eq 1 ]; then
      int_composer="$x"
    else
      int_composer="$int_composer, $x"
    fi

  done

  if [ $counter -gt 1 ]; then
    info_message "se detectaron $counter interfaces de red: $int_composer "
  else
    info_message "se detecto una interfaz de red: $int_composer"
  fi
}

open_port()
{

    # protocol=$3 # not yet v 1.0 - fuzzy connect
    destination_ip=$1
    destination_port=$2

    min_bash_version=3.0

    #what we have.


    use_nc=0
    use_bash=0
    use_perl=0

    if [ -x /usr/bin/nc ]; then
      use_nc=1
      nc_path="/usr/bin/nc"
    fi

    if [ -x /usr/bin/perl ]; then
      use_perl=1
      perl_path="/usr/bin/perl"
    fi
    
    # obtengamos la version de bash
    # si es mayor a 3 usemos builtins
    if [ "$(version "$min_bash_version")" -gt "$(version "$BASH_VERSION")" ]; then
      error_message "La version de bash es menor a $min_version.. "
    else
      use_bash=1
      use_perl=0
      use_nc=0
    fi

    

    sum=`expr $use_nc + $use_bash + $use_perl`

    if [ "$sum" -eq 0 ]; then
      error_message "No se puede determinar como abrir puertos"
    else
      # lets open this shit

      open_port=0
      DEBUG=0

      if [ $DEBUG -eq 1 ]; then
        echo "parameters"
        echo "destination: >$destination_ip<"
        echo "port: >$destination_port<"
        echo "use_nc: $use_nc, use_bash: $use_bash, use_perl: $use_perl"
        echo 
      fi

      # we don't care about protocol now, todo es tcp !!

      if [ $use_perl -eq 1 ]; then
        composer="$perl_path -MIO::Socket::INET -e 'exit(! defined( IO::Socket::INET->new(\"$destination_ip:$destination_port\")))'"
        result=`$composer`
        if [ $DEBUG -eq 1 ]; then
          echo "composer >$composer<"
          echo "salida >$result<"
        fi
        if [ $composer -eq 1 ]; then
          open_port=1
        fi
      fi


      # probar que usamos para abrir el puerto.
      if [ $use_nc -eq 1 ]; then 
        # usemos netcat
        composer="$nc_path -z -w 2 -v $destination_ip $destination_port 2>/dev/null; echo $?"
        if [ $DEBUG -eq 1 ]; then
          echo "composer >$composer<"
        fi

        result=`$composer`
        result2=`echo $result | grep "succeeded" | wc -l`


        if [ $DEBUG -eq 1 ]; then
          echo "result >$result<"
        fi

        if [ "$result2" == "" ]; then
          error_message "No se puede determinar si el puerto esta abierto o no, error de netcat ?"
          exit 250
        fi

        if [ $result2 -gt 0 ]; then
          # ok, puerto abierto
          open_port=1
        fi
      fi

      if [ $use_nc -eq 0 -a $use_bash -eq 1 ]; then
        # usemos bash
        composer=`timeout 3 bash -c cat < /dev/null 2>&1 > /dev/tcp/$destination_ip/$destination_port; echo $?`
        composer_result=$composer

        if [ $DEBUG -eq 1 ]; then
          echo "composer      >$composer<"
          echo "Composer result:  >$composer_result<"
        fi

        if [ $composer_result -eq 0 ]; then
          # puerto abierto
          open_port=1
        else
          open_port=0
        fi
      fi

      if [ $DEBUG -eq 1 ]; then
        echo "regresando: $open_port"
      fi
    
      echo $open_port

    fi

}


check_selinux()
{

  DEBUG=0

  # tenemos selinux en est caja? esta activado ?
  if [ -d  /etc/selinux ]; then
    info_message "SELinuxdir: /etc/selinux"
    # ok ahi esta el directorio, busquemos el binario
    if [ -x /usr/sbin/sestatus ]; then
      # obtengamos la configuracion
      selinux_status=`/usr/sbin/sestatus | grep "SELinux status:" | awk '{ print $3 }'`
      selinux_mode=`/usr/sbin/sestatus | grep "Current mode:" | awk '{ print $3 }'`
      echo "Status: $selinux_status, Mode: $selinux_mode"
    fi

    if [ "$selinux_status" = "enabled" -a "$selinux_mode" = "enforcing" ]; then
      ok_message "Selinux activado y habilitado en enforcing mode"
    else
      error_message "Selinux se encuentra en la distribucion pero no se encuentra habilitado y en enforcing mode"
    fi
  else
    error_message "No se encuentra selinux en el path estandar ? - No se tiene selinux ?"
  fi


}

message()
{
  message=$1
        YELLOW='\033[0;33m'
        NC='\033[0m' # No Color

  echo -e "${YELLOW}$message${NC}"
  echo "=============================================="
}

i_need_root()
{
  # valida que este proceso se ejecute como el usuario root

  # que id tengo ?

  if [ -x /usr/bin/id ]; then
    my_id=`/usr/bin/id -u`
    if [ $my_id -eq 0 ]; then
      im_root=1
    else
      im_root=0
      warning_message "Este script requiere ser ejecutado como el usuario \"root\""
      bye
    fi
  else
    info_message "No se pude determinar si soy root"
  fi
}


normalize_string()
{
  # removes enters, spaces from shell returning varialbes
  # 

  normalize_string_input=$1
  normalize_string_input_1=${normalize_string_input//[$'\t\r\n']}
  normalize_string_output=${normalize_string_input_1// /}

  echo "$normalize_string_output"

}

settle_down()
{
	# settle down (wait) 
	# espera por un numero de segundos
	time_to_wait=$1

	for x in $(seq 1 $time_to_wait);
	do

		for x in . o O "*" "+"
		do
			echo -e "$x\c"
			echo -en "\033[1D"
			sleep .3
		done

		echo -en "\033[1C"
		echo -e " ... \c"
	done
	echo

}


boxmetop()
{
  # boxes an important message 
  message=$1
  CYAN='\033[0;36m'
  NC='\033[0m' # No Color

  # roof
  message_len_1=`echo "$message" | wc -c`
  message_len_2=`expr $message_len_1 + 3`
  echo -e "+\c"
  for i in $(seq 1 $message_len_2)
  do
    echo -e "-\c"
  done
  echo -e "+"

  # side
  echo -e "|  \c"
  echo -e "${CYAN}$message${NC}\c"
  echo -e "  |"

  # bottom
  echo -e "+\c"
  for i in $(seq 1 $message_len_2)
  do
    echo -e "-\c"
  done
  echo -e "+\n"

}

###### END GLOBAL SUBS



#
#
# Oracle12 specific routines
#
#
#
# probado con: Oracle Database 12c Enterprise Edition Release 12.2.0.1.0 - 64bit Production
# corriendo en: RHEL release 7.4.x 
# Default installations.
#



validate_oracle()
{


if [ -f /etc/oratab ]; then
	# obtengamos datos del oratab

	oratab_line=`cat /etc/oratab | grep -v '^$\|^\s*\#'`

	if [ "$oratab_line" = "" ]; then
		warning_message "No se puede procesar el archivo /etc/oratab"
		bye
	fi

	oracle_sid=`echo $oratab_line | cut -d":" -f1`
	oracle_db_path=`echo $oratab_line | cut -d":" -f2`

	#info_message "Oracle SID: $oracle_sid"
	#info_message "Oracle path: $oracle_db_path"

	if [ "$oracle_sid" = "" ]; then
		warning_message "No se puede determinar el Oracle SID !"
		bye
	fi

	if [ "$oracle_db_path" = "" ]; then
		warning_message "No se puede determinar el Oracle path"
		bye
	fi

	# validemos el path

	if [ -d "$oracle_db_path" ]; then
		# ok es un directorio, existe el binario ahi ?
		sqlplus_path="$oracle_db_path/bin/sqlplus"
		if [ -x "$sqlplus_path" ]; then
			info_message "Sqlplus detectado"
		fi
	else
		warning_message "El directorio de oracle $oracle_db_path, no existe !??!"
		bye
	fi
	oratab_processed=1
else
	warning_message "No se puede detectar el archivo de configuracion /etc/oratab"
	warning_message "Esta instalado oracle 12 en este equipo ?"
	bye
fi

# validemos si esta ejecutandose oracle

oracle_listener=`ps -ef | grep "tnslsnr LISTENER" | grep -v grep | wc -l`

if [ $oracle_listener -gt 0 ]; then
	# aparentemente esta ahi ejecutandose
	# validemos 
	# obtengamos el path 
	info_message "tnslsnr LISTENER #$oracle_listener"
	# busquemos procesos de oracle ora_*_$sid
	if [ $oratab_processed -eq 1 ]; then
		# we have a sid 
		ora_process=`ps -ef | grep -e "ora_.*_$oracle_sid" | grep -v grep | wc -l`

		if [ $ora_process -gt 0 ]; then
			# nice..
			oracle_running=1
		fi
	fi
else
	# no esta ejecutandose oracle, se proceso oratab ?
	if [ $oratab_processed -eq 1 ]; then
		warning_message "No esta ejecutandose ninguna instancia de oracle .."
		bye
	fi
fi


}



check_running_user()
{
	# validar que el listener se ejecute con un usuario que no sea root
	# return running user
	running_user=`ps -ef | grep "tnslsnr LISTENER" | grep -v grep | awk '{ print $1 }'`

	if [ "$running_user" = "root" ]; then
		# fuck..
		error_message "Usuario que ejecuta la instancia: root"
	else
		ok_message "Usuario que ejecuta la instancia: $running_user"
		oracle_user=$running_user

    # obtengamos el home directory del usuario
    user_id=`id -u $running_user`
    oracle_user_home=`cat /etc/passwd | grep "$user_id" | cut -d":" -f6`
    info_message "Oracle User Home: $oracle_user_home"
    if [ -d "$oracle_user_home" ]; then
      # busquemos en su .bash_profile la variable ORACLE_HOME
      if [ $(search_file "$oracle_user_home/.bash_profile" "^\s*export ORACLE_HOME.*") -eq 0 ]; then
        warning_message "El usuario que ejecuta la instancia no tienene .bash_profile ?"
      else
        boxmetop "usuario $running_user validado !"
      fi
    else
        warning_message "No existe el home directory del usuario que ejecuta la instancia ??"
    fi
	fi

}


execute_sqlplus()
{
	# necesitamos el sqlplus path, el usuario, el comando, y algo que buscar
	sql_command=$1
	extract_line=$2
	execute_sqlplus_output=""

	# creamos el archivo sql
	cmd_file="/tmp/sqltemp.$$"
	echo "connect sys/$oracle_sys_password as sysdba;" > $cmd_file
	echo "whenever sqlerror exit sql.sqlcode;" >> $cmd_file
	echo "set echo off" >> $cmd_file 
	echo "set heading off" >> $cmd_file
	echo "$sql_command" >> $cmd_file
	echo "quit" >> $cmd_file
	# si existe ya un archivo de salida eliminarlo
	#if [ -f /tmp/sql.out.$$ ]; then
	#	rm -f /tmp/sql.out.$$
	#fi
  # <- nope.. in memory transfer via pipe a grep
  # 
	# en una instalacion estandar de oracle, el usuario que ejecuta la instancia
	# tiene en su profile los paths necesarios para ejecutar sqlplus -s /nolog
  # 
  # aqui vemos que tan bien se sigue la documentacion de instalacion.
  #

	#settle_down 3
	cmd_composer="su - $oracle_user -c \"sqlplus -s /nolog < /tmp/sqltemp.$$\" | grep -e \"$extract_line\""
	
	#ejecutemos el comando and cross fingers 
	execute_sqlplus_output=`eval $cmd_composer`

	# validemos si la salida no esta vacia
	if [ "$execute_sqlplus_output" = "" ]; then
		warning_message "No se obtuvo una salida al comando de sqlplus $sql_command"
		bye # no puedo ejecutar sqlplus .. !!???
	fi

  if [ -f /tmp/sqltemp.$$ ]; then
    # erase our aux file
    rm -f /tmp/sqltemp.$$
  fi

	echo "$execute_sqlplus_output"

}

check_sqlplus()
{
	# validar que podamos ejecutar sqlplus como el usuario
	# de oracle

	sqlplus_ok=0

	# probemos ejecutar un comando simple de sqlplus

	test_output=$(execute_sqlplus "SELECT * FROM V\$VERSION;"  "CORE")

	# validar que tengamos un core
	dummy=`echo $test_output | awk '{ print $1 }'`
	if [ "$dummy" = "CORE" ]; then
		sqlplus_ok=1
    # really nice.. esta instalado de forma predecible.. Bien !
	else
		sqlplus_ok=0
    warning_message "sqlplus regreso un resultado inesperado"
	fi

	echo $sqlplus_ok

}



validate_oracle_version()
{
  # valida que la version de oracle sea mayor que la version 12.1.0.2
  # nasty bug en version 12.1.0.x
  # https://www.cvedetails.com/cve/CVE-2016-0499/
  min_version="12.1.0.2"

  vo_composer=$(execute_sqlplus "SELECT * FROM V\$VERSION;"  "CORE")
  oracle_version=`echo $vo_composer | awk '{ print $2 }'`
  oracle_mode=`echo $vo_composer| awk '{ print $3 }'`

  info_message "Version: $oracle_version, Operation mode: $oracle_mode"
  if [ "$(version "$min_version")" -gt "$(version "$oracle_version")" ]; then
    error_message "Version <= a 12.1.0.2 se suguiere actualizar"
  else
    ok_message "Version $oracle_version > $min_version"
  fi

}


validate_oracle_os_accounts()
{
  # valida que no se utilicen cuentas del OS para el acceso (OS$ comunmente)
  
  # obtengamos el prefix del OS
  os_prefix_composer=$(execute_sqlplus "show parameter os_authent_prefix;"  "string")

  os_prefix_1=`echo $os_prefix_composer | awk '{ print $3 }'`
  # oracle internally stores objects in the data dictionary in uppercase.
  # So it is not possible to have a lowercase username.
  os_prefix=`echo $os_prefix_1 | tr [a-z] [A-Z]`

  info_message "OS Prefix: $os_prefix"

  get_os_users_1=$(execute_sqlplus "select count(*) from dba_users where username like '$os_prefix%';" "^\s*[0-9]*$")
  get_os_users=$(normalize_string "$get_os_users_1")

  info_message "Os Users found: $get_os_users"

  if [ $get_os_users -gt 0 ]; then
    error_message "Se encontraron cuentas del sistema operativo"
  else
    ok_message "No se encuentran habilitadas cuentas del sistema operativo"
  fi

}


validate_audit()
{
  # valida que se encuentre habilitada la auditoria
  # y el audit trail extended
  audit_trial_1=$(execute_sqlplus "show parameter AUDIT_SYS_OPERATIONS;" "boolean")
  audit_trial=`echo $audit_trial_1 | awk '{ print $3 }'`

  info_message "Audit Sys Operations: $audit_trial"

  if [ "$audit_trial" = "TRUE" ]; then
    ok_message "Auditoria habilitada"
  else
    error_message "Auditoria deshabilitada"
  fi

  audit_type_1=$(execute_sqlplus "SHOW PARAMETER AUDIT_TRAIL" "string")
  audit_type_2=`echo $audit_type_1 | awk -F"string" '{ print $2 }'`
  audit_type=$(normalize_string "$audit_type_2")

  info_message "Audit type: $audit_type"

  if [ "$audit_type" = "DB,EXTENDED" -o "$audit_type" = "XML,EXTENDED" ]; then
    ok_message "Auditoria extendida habilitada"
  else
    error_message "No se detecta la auditoria extendida"
  fi

}

validate_encryption()
{
  # valida que se cuente con columnas encriptadas
  #

  encrypted_columns_num_1=$(execute_sqlplus "select count(*) from DBA_ENCRYPTED_COLUMNS;" "^\s*[0-9]*$")
  encrypted_columns_num=$(normalize_string "$encrypted_columns_num_1")
  info_message "Columnas encriptadas encontradas: $encrypted_columns_num"

  if [ $encrypted_columns_num -eq 0 ]; then
    error_message "No se tiene habilitada la encripcion de datos ?"
  else
    ok_message "Se detecto encripcion de datos habilitada"
  fi

}



validate_banner()
{
  # valida el banner de identificacion de la base de datos
  # https://docs.oracle.com/cd/B28359_01/server.111/b28320/initparams215.htm#REFRN10275
  # validar que sec_return_server_release_banner sea FALSE

  banner_enabled_1=$(execute_sqlplus "show parameter sec_return_server_release_banner;" "boolean")
  banner_enabled=`echo $banner_enabled_1 | awk '{ print $3}'`

  info_message "sec_return_server_release_banner: $banner_enabled"

  if [ "$banner_enabled" = "FALSE" ]; then
    ok_message "Banner de identificacion deshabilitado"
  else
    error_message "Banner de identificacion de la base de datos habilitado"
  fi


}

validate_max_failed_login()
{
  # valida que exista la variable sec_max_failed_login_attempts y tenga un valor maximo de 3
  max_tries=4

  max_failed_1=$(execute_sqlplus "show parameter sec_max_failed_login_attempts;" "integer")
  #info_message ">$max_failed_1<"
  max_failed_2=`echo $max_failed_1 | awk '{ print $3 }'`
  max_failed=$(normalize_string "$max_failed_2")

  info_message "sec_max_failed_login_attempts: $max_failed"

  if [ $max_failed -gt 0 -a $max_failed -lt $max_tries ]; then
    ok_message "Se localizo la variable sec_max_failed_login_attempts"
  else
    error_message "La variable sec_max_failed_login_attempts debera de exisir con un valor maximo de 3"
  fi
}

validate_default_passwords()
{
  # valida que no existan registros en la tabla de passwords por default de oracle
  # en caso de encontrarse validar si se pueden bloquear las cuentas o cambiar el password

  users_with_dpass_1=$(execute_sqlplus "select count(USERNAME) FROM DBA_USERS_WITH_DEFPWD;" "^\s*[0-9]*$")
  users_with_dpass=$(normalize_string "$users_with_dpass_1")
  #users_with_dpass_2=${users_with_dpass_1//[$'\t\r\n']}
  #users_with_dpass=${users_with_dpass_2// /}
  if [ $users_with_dpass -gt 0 ]; then
    error_message "Existen $users_with_dpass cuentas en la tabla DBA_USERS_WITH_DEFPWD"
  else
    ok_message "No se encontraron cuentas con password de default"
  fi

}


check_client_logon_version()
{
  # valida que la version de protocolos de autenticacion del cliente sea
  # $version_minimal en sqlnet.ora
  # referencias:
  # https://docs.oracle.com/database/121/DBSEG/authentication.htm#DBSEG30324

  version_minimal="12a"

  if [ $(search_file "$oracle_db_path/network/admin/sqlnet.ora" "SQLNET.ALLOWED_LOGON_VERSION_CLIENT=12a") -eq 1 ]; then
    ok_message "Se localizo directiva para permitir unicamente clientes con version 12a"
  else
    error_message "No se localizo la directiva para permitir unicamente clientes con la version 12a"
  fi

}

# check_sqlnet_autentication()
# {

#   # valida que la version se cuente con una directiva SQLNET.AUTHENTICATION_SERVICES
#   # en sqlnet.ora
#   # referencias:
#   # https://docs.oracle.com/cd/E11882_01/network.112/e10835/sqlnet.htm#NETRF199
#   # 
#   # none for no authentication methods, including Microsoft Windows native operating 
#   # system authentication. When SQLNET.AUTHENTICATION_SERVICES is set to none, a valid user 
#   # name and password can be used to access the database.
#   # no funciona bien con oracle12x.. 

#   if [ $(search_file "$oracle_db_path/network/admin/sqlnet.ora" "SQLNET.AUTHENTICATION_SERVICES=(none)") -eq 1 ]; then
#     ok_message "Se econtro directiva para no permitir autenticacion del sistema operativo"
#   else
#     error_message "SQLNET.AUTHENTICATION_SERVICES=(none)  no encontrado"
#   fi


# }


validate_tcps_listener()
{
  # validar que existen servicios con tcps (tls https)
  # esto indica que el trafico de red al puerto de servicio esta encriptado

  listener_file="$oracle_db_path/network/admin/listener.ora"

  if [ -f $listener_file ]; then
    info_message "listener.ora localizado"

    # check what this thing has
    if [ $(search_file "$listener_file" "PROTOCOL = TCPS") -eq 1 ]; then
      ok_message "Se detectan puertos encriptados de servicio"
    else
      error_message "No se detectan puertos de servicio encriptados (TCPS)"
    fi
  fi
}

validate_online_admin_restrictions()
{
  # Nice explanation
  # http://arup.blogspot.mx/2008/08/why-should-you-set-adminrestrictionslis.html
  # 
  # busquemos algun ADMIN_RESTRICTIONS_.*=on de acuerdo a:
  # https://docs.oracle.com/cd/B10501_01/network.920/a96581/listener.htm#500821

  listener_file="$oracle_db_path/network/admin/listener.ora"

  if [ -f $listener_file ]; then
    info_message "listener.ora localizado"

    # check what this thing has
    if [ $(search_file "$listener_file" "ADMIN_RESTRICTIONS_.*=on") -eq 1 ]; then
      ok_message "Se detectan listeners con ADMIN RESTRICTIONS"
    else
      error_message "No se detecta configuracion de listeners con ADMIN_RESTRICTIONS"
    fi
  fi


}


validate_oracle_ports()
{
  # validar que el puerto de administracion 5500 no se encuentre en todas las interfaces

  # obtener las interfaces de red en un array
  interfaces_to_array

  interfaces_counter=0

  for x in "${INTERFACES_ARRAY[@]}"
  do
    info_message "validando puerto 5500 en ip: $x"
    if [ $(open_port "$x" "5500") -eq 1 ]; then
      interfaces_counter=`expr $interfaces_counter + 1`
      info_message "puerto abierto: $x:5500"
    fi
  done


  if [ $interfaces_counter -eq 0 ]; then
    ok_message "No se detecta el puerto 5500 abierto"
  fi
  if [ $interfaces_counter -eq 1 ]; then
    ok_message "Se detecta el puerto 5500 solo en una interface"
  fi
  if [ $interfaces_counter -gt 1 ]; then
    error_message "Se detecta el puerto 5500 en mas de una interface"
  fi
 
 }





#}


#
#
#  __main()__
#
#
#


process_string=""

echo
echo "Oracle Database Enterprise 12.x best practices validator v$version"
echo "=================================================================="
echo

i_need_root

# limpiemos globales

oracle_sid=""
oracle_db_path=""
sqlplus_path=""
oracle_running=0
oratab_processed=0
oracle_user=""
oracle_sys_password=""


# here we go #### TEST PHASE


validate_oracle

info_message "Oracle SID   : $oracle_sid"
info_message "Oracle Path  : $oracle_db_path"
info_message "sqlplus path : $sqlplus_path"
echo

# ok, al parecer esta ejecutandose y se detecto archivo de configuracion
# creemos el archivo de reporte
today=`date +%Y-%m-%d`
nombre_archivo="Reporte_hardening_oracle12_$today.csv"
# clean out last file
echo "" > $nombre_archivo

check_running_user


################### CHECKING PHASE

## FILES STUFF

message "Validando puerto de em"
validate_oracle_ports
echo

# message "Validando autenticacion de sistema operativo"
# check_sqlnet_autentication
# echo

message "Validando restricciones de admin"
validate_online_admin_restrictions
echo

message "Validando puertos de servicio encriptados"
validate_tcps_listener
echo

#validate_case_sensitive_logon

message "Validando protocolo de autenticacion para clientes"
check_client_logon_version
echo


message "Validando SELinux"
check_selinux
echo



#SQLPLUS STUFF
# obtener el password de sys, usar el $oracle_user para acceder como sys
echo
echo "Se requiere el password de SYS para validar parametros de la base de datos"
echo "Introduzca el password del usuario SYS o presione CTRL-C para cancelar el script"
echo -e "Password : \c"
read sys_user_password
echo

if [ "$sys_user_password" = "" ]; then
	warning_message "El password esta vacio.... "
fi

oracle_sys_password="$sys_user_password"


if [ $(check_sqlplus) -eq 0 ]; then
	error_message "No se puede ejecutar sqlplus, no se validan parametros de base de datos"
else
  boxmetop "sqlplus funcional !"

  sleep 3
  echo 
  echo

  message "Validando version de base de datos"
  validate_oracle_version
  echo

  message "Validando uso de cuentas de sistema operativo"
  validate_oracle_os_accounts
  echo

  #validate_remote_login_passwordfile 

  message "Validando auditoria"
  validate_audit
  echo

  message "Validando encripcion de datos"
  validate_encryption
  echo

  message "Validando banner de identificacion"
  validate_banner
  echo

  message "Validando variable max_failed_login"
  validate_max_failed_login
  echo

  message "Validando tabla de default passwords"
  validate_default_passwords
  echo

  #validate_sensitive_logon

fi


echo
echo "=========================================================="
echo "Validacion finalizada, su reporte se encuentra en el archivo: $nombre_archivo"
echo 
echo
exit 1

