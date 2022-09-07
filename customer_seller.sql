--Function to check if phone number is valid

create or replace function fn_isvalid_ph(ph varchar2)
return varchar2
is
ex_invalid_length exception;
begin
if length(ph)<10 or length(ph)>10 then
raise ex_invalid_length;
else return 'Valid ph';
end if;
exception
when ex_invalid_length then
return 'Invalid phone number';
end;


--Function to check if email is valid

create or replace function fn_isvalid_email(email varchar2)
return varchar2
is
fn_isvalid   boolean;
ex_invalid_email exception;
begin
fn_isvalid := REGEXP_LIKE (email,
                   '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$');
if fn_isvalid then return 'Valid email';
else
raise ex_invalid_email;
end if;
Exception
   when ex_invalid_email then
   return 'Not a valid email address';
end;


--Function to check if password is valid                
                   
create or replace function fn_isvalid_pw(pw varchar2)
return varchar2
is
fv_digcount number:= REGEXP_COUNT (pw, '\d',1,'i');
fv_spcount number:= REGEXP_COUNT (pw, '\W',1,'i');
ex_invalid_length exception;
ex_no_digits exception;
ex_no_special_character exception;
begin
if length(pw)<8 or length(pw)>12 then
raise ex_invalid_length;
elsif fv_digcount=0 then
raise ex_no_digits;
elsif fv_spcount=0 then
raise ex_no_special_character;
else return 'Password set';
end if;
Exception
when ex_invalid_length then return'Invalid length!';
when ex_no_digits then return 'Must contain at least 1 digit!';
when ex_no_special_character then return 'Must contain at least 1 special character!';
end;


--Hash function to convert plaintext password into hashed form

CREATE OR REPLACE FUNCTION GEN_PW_HASH(PWD NVARCHAR2)
RETURN NVARCHAR2
IS
  l_hash VARCHAR2 (2000);
BEGIN
    l_hash := DBMS_CRYPTO.HASH (src => utl_i18n.string_to_raw (PWD, 'AL32UTF8'), typ => DBMS_CRYPTO.hash_sh1);
    RETURN  l_hash;
END GEN_PW_HASH;

--Sequence to generate user_ids

CREATE SEQUENCE login_seq
 START WITH     200
 INCREMENT BY   1
 NOCACHE
 NOCYCLE


--package containing procedures to create new user or update user details

create or replace package pkg_user as
procedure p_new_user(lv_fname varchar2,lv_lname varchar2,lv_setpw varchar2,
lv_address varchar2,lv_ph varchar2,lv_email varchar2,lv_dob varchar2,
lv_country varchar2,lv_pcode number,lv_city varchar2,lv_state varchar2);
procedure p_new_user(lv_name varchar2,lv_setpw varchar2,lv_ph varchar2);
procedure p_ph_update(lv_userid varchar2,lv_pw varchar2,lv_ph varchar2);
procedure p_email_update(lv_userid varchar2,lv_pw varchar2,lv_email varchar2);
procedure p_pw_update(lv_userid varchar2,lv_pw varchar2,lv_new_pw varchar2);
end;

create or replace package body pkg_user as
    --for new customer registraion
    procedure p_new_user(lv_fname varchar2,lv_lname varchar2,lv_setpw varchar2,
    lv_address varchar2,lv_ph varchar2,lv_email varchar2,lv_dob varchar2,
    lv_country varchar2,lv_pcode number,lv_city varchar2,lv_state varchar2)
    is
    lv_msg varchar2(30);
    lv_pwhash varchar2(50);
    lv_custid number(10):=login_seq.nextval;
    begin
        if fn_isvalid_pw(lv_setpw)<>'Password set' then 
            lv_msg:=fn_isvalid_pw(lv_setpw);
            dbms_output.put_line(lv_msg);
        elsif fn_isvalid_ph(lv_ph)<>'Valid ph' then
            lv_msg:=fn_isvalid_ph(lv_ph);
            dbms_output.put_line(lv_msg);
        elsif fn_isvalid_email(lv_email)<>'Valid email' then
            lv_msg:=fn_isvalid_email(lv_email);
            dbms_output.put_line(lv_msg);
        else
            lv_pwhash:=gen_pw_hash(lv_setpw);
            insert into login_details values(lv_custid, lv_pwhash, 'customer');
            insert into customer values(lv_custid,lv_fname,lv_lname,null,lv_address,lv_ph,lv_email,lv_dob,lv_country,lv_pcode,lv_city,lv_state);
            dbms_output.put_line('New customer registered');
        end if;
    end;
    
    --for new seller registration
    
    procedure p_new_user(lv_name varchar2,lv_setpw varchar2,lv_ph varchar2)
    is
    lv_msg varchar2(30);
    lv_pwhash varchar2(50);
    lv_sellerid number(10):=login_seq.nextval;
    begin
        if fn_isvalid_pw(lv_setpw)<>'Password set' then 
            lv_msg:=fn_isvalid_pw(lv_setpw);
            dbms_output.put_line(lv_msg);
        elsif fn_isvalid_ph(lv_ph)<>'Valid ph' then
            lv_msg:=fn_isvalid_ph(lv_ph);
            dbms_output.put_line(lv_msg);
        else
            lv_pwhash:=gen_pw_hash(lv_setpw);
            insert into login_details values(lv_sellerid, lv_pwhash, 'seller');
            insert into seller values(lv_sellerid,lv_name,null,lv_ph);
            dbms_output.put_line('New seller registered');
        end if;
    end;
    
    --for updating phone of existing user
    
    procedure p_ph_update(lv_userid varchar2,lv_pw varchar2,lv_ph varchar2)
    is
    lv_msg varchar2(30);
    lv_usertype varchar2(30);
    lv_pwhash varchar2(50);
    lv_pwcheck varchar(50);
    begin
        select password into lv_pwcheck from login_details where login_id=lv_userid;
        select user_type into lv_usertype from login_details where login_id=lv_userid;
        if sql%found then
            lv_pwhash:=gen_pw_hash(lv_pw);
            if lv_pwcheck!=lv_pwhash then
                dbms_output.put_line('Incorrect password');
            else
                if fn_isvalid_ph(lv_ph)<>'Valid ph' then
                    lv_msg:=fn_isvalid_ph(lv_ph);
                    dbms_output.put_line(lv_msg);
                else
                    if lv_usertype='customer' or lv_usertype='CUSTOMER' or lv_usertype='Customer' then 
                        update customer set phone=lv_ph where customer_id=lv_userid;
                    else
                        update seller set phone=lv_ph where seller_id=lv_userid;
                    end if;
                    dbms_output.put_line('Phone number updated');
                end if;
            end if;
        end if;
        Exception
        when no_data_found then
            dbms_output.put_line('No Customer_id or Seller_id found for entered User_id');   
    end;
    
    --for updating email of existing customer
    
    procedure p_email_update(lv_userid varchar2,lv_pw varchar2,lv_email varchar2)
    is
    lv_msg varchar2(30);
    lv_pwhash varchar2(50);
    lv_pwcheck varchar(50);
    begin
        select password into lv_pwcheck from login_details where login_id=lv_userid;
        if sql%found then
            lv_pwhash:=gen_pw_hash(lv_pw);
            if lv_pwcheck!=lv_pwhash then
                dbms_output.put_line('Incorrect password');
            else
                if fn_isvalid_email(lv_email)<>'Valid email' then
                    lv_msg:=fn_isvalid_email(lv_email);
                    dbms_output.put_line(lv_msg);
                else
                    update customer set email=lv_email where customer_id=lv_userid;
                    dbms_output.put_line('Email updated');
                end if;
            end if;
        end if;
        Exception
        when no_data_found then
            dbms_output.put_line('Customer_id not found');   
    end;
    
    --for updating password of existing user
    
    procedure p_pw_update(lv_userid varchar2,lv_pw varchar2,lv_new_pw varchar2)
    is
    lv_msg varchar2(30);
    lv_usertype varchar2(30);
    lv_pwhash varchar2(50);
    lv_pwcheck varchar(50);
    begin
        select password into lv_pwcheck from login_details where login_id=lv_userid;
        if sql%found then
            lv_pwhash:=gen_pw_hash(lv_pw);
            if lv_pwcheck!=lv_pwhash then
                dbms_output.put_line('Incorrect password');
            else
                if fn_isvalid_pw(lv_new_pw)<>'Password set' then
                    lv_msg:=fn_isvalid_pw(lv_pw);
                    dbms_output.put_line(lv_msg);
                else
                    update login_details set password=lv_new_pw where login_id=lv_userid;
                    dbms_output.put_line('Password changed');
                end if;
            end if;
        end if;
        Exception
        when no_data_found then
            dbms_output.put_line('No Customer_id or Seller_id found for entered User_id');   
    end;
    
end;