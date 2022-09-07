-----login details

insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(101,1234,'CUSTOMER');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(102,1235,'seller');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(103,1236,'CUSTOMER');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(104,1237,'seller');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(105,1238,'CUSTOMER');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(106,1239,'seller');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(107,1231,'CUSTOMER');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(108,1235,'seller');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(109,1230,'CUSTOMER');
insert into LOGIN_DETAILS(LOGIN_ID,PASSWORD,USER_TYPE)VALUES(110,1232,'seller');

----------------seller
insert into SELLER(SELLER_ID,SELLER_NAME,SELLER_RATING,PHONE)values(102,'swapnil',2,6574321234);
insert into SELLER(SELLER_ID,SELLER_NAME,SELLER_RATING,PHONE)values(106,'tasneem',2,4574321234);
insert into SELLER(SELLER_ID,SELLER_NAME,SELLER_RATING,PHONE)values(108,'ritul',3,5474321234);
insert into SELLER(SELLER_ID,SELLER_NAME,SELLER_RATING,PHONE)values(110,'rohan',2,8574321234);

------categories

insert into CATEGORIES(CATEGORY_ID)values(401);
insert into CATEGORIES(CATEGORY_ID)values(402);
insert into CATEGORIES(CATEGORY_ID)values(403);
insert into CATEGORIES(CATEGORY_ID)values(404);
insert into CATEGORIES(CATEGORY_ID)values(405);


----------product
insert into PRODUCT(PRODUCT_ID,CATEGORY_ID,PRODUCT_NAME,BRAND,QUANTITY,PRICE,DISCOUNT,DISCOUNTED_PRICE,DESCRIPTION,QUANTITY_IN_STOCK,IMAGE)
values(301,401,'shoes','A6',10,300,50,150,NULL,10,NULL);

insert into PRODUCT(PRODUCT_ID,CATEGORY_ID,PRODUCT_NAME,BRAND,QUANTITY,PRICE,DISCOUNT,DISCOUNTED_PRICE,DESCRIPTION,QUANTITY_IN_STOCK,IMAGE)
values(302,402,'shoes','A6',10,300,50,150,NULL,10,NULL);

insert into PRODUCT(PRODUCT_ID,CATEGORY_ID,PRODUCT_NAME,BRAND,QUANTITY,PRICE,DISCOUNT,DISCOUNTED_PRICE,DESCRIPTION,QUANTITY_IN_STOCK,IMAGE)
values(303,403,'T- SHIRT','AZ',10,300,50,150,NULL,10,NULL);

insert into PRODUCT(PRODUCT_ID,CATEGORY_ID,PRODUCT_NAME,BRAND,QUANTITY,PRICE,DISCOUNT,DISCOUNTED_PRICE,DESCRIPTION,QUANTITY_IN_STOCK,IMAGE)
values(304,404,'TOPS','HM',10,300,50,150,NULL,10,NULL);

insert into PRODUCT(PRODUCT_ID,CATEGORY_ID,PRODUCT_NAME,BRAND,QUANTITY,PRICE,DISCOUNT,DISCOUNTED_PRICE,DESCRIPTION,QUANTITY_IN_STOCK,IMAGE)
values(305,405,'WATCH','FIRE BOLT',10,300,50,150,NULL,10,NULL);




----product seller
insert into PRODUCT_SELLER(PRODUCT_ID,SELLER_ID)values(301,102);
insert into PRODUCT_SELLER(PRODUCT_ID,SELLER_ID)values(302,103);
insert into PRODUCT_SELLER(PRODUCT_ID,SELLER_ID)values(303,106);
insert into PRODUCT_SELLER(PRODUCT_ID,SELLER_ID)values(304,108);



--------customer
insert into CUSTOMER(CUSTOMER_ID,FIRST_NAME,LAST_NAME,ADDRESS,PHONE,EMAIL,DATEOFBIRTH,COUNTRY,POSTAL_CODE,CITY,STATE)
VALUES(101,'sneha',' santra','kpotownhall',3214567891,'sayan','10-dec-22','india',812001,'durgapur','kolkata');

insert into CUSTOMER(CUSTOMER_ID,FIRST_NAME,LAST_NAME,ADDRESS,PHONE,EMAIL,DATEOFBIRTH,COUNTRY,POSTAL_CODE,CITY,STATE)
VALUES(103,'sayan',' santra','townhall',3414567891,'saya','11-dec-22','india',812001,'durgapur','kolkata');



----------cart
insert into Cart(CART_ID,CUSTOMER_ID,CART_STATUS,TOTAL_PRICE,DELIVERY_STATUS)
VALUES(901,101,'available',2000,'pending');

insert into Cart(CART_ID,CUSTOMER_ID,CART_STATUS,TOTAL_PRICE,DELIVERY_STATUS)
VALUES(902,103,'available',4000,'completed');


insert into Cart(CART_ID,CUSTOMER_ID,CART_STATUS,TOTAL_PRICE,DELIVERY_STATUS)
VALUES(903,null,'available',5000,'pending');



---------payment

insert into PAYMENT(PAYMENT_ID,CUSTOMER_ID,PAYMENT_AMOUNT,PAYMENT_MODE,PAYMENT_DATE,PAYMENT_STATUS)
VALUES(801,103,50,'online','12-feb-22','completed');

insert into PAYMENT(PAYMENT_ID,CUSTOMER_ID,PAYMENT_AMOUNT,PAYMENT_MODE,PAYMENT_DATE,PAYMENT_STATUS)
VALUES(802,101,50,'cash','15-jan-21','completed');

insert into PAYMENT(PAYMENT_ID,CUSTOMER_ID,PAYMENT_AMOUNT,PAYMENT_MODE,PAYMENT_DATE,PAYMENT_STATUS)
VALUES(803,null,50,'online','12-oct-22','pending');

-----cart payment

insert into CART_PAYMENT(CART_ID,PAYMENT_ID)
VALUES(901,801);

insert into CART_PAYMENT(CART_ID,PAYMENT_ID)
VALUES(902,802);

insert into CART_PAYMENT(CART_ID,PAYMENT_ID)
VALUES(903,803);



--------review

insert into REVIEW(PRODUCT_ID,REVIEW_TITLE,PRODUCT_RATING,OTHER_COMMENTS,CUSTOMER_ID,REVIEW_DATE)
VALUES(301,'xyz',null,null,101,'10-jan-19');

insert into REVIEW(PRODUCT_ID,REVIEW_TITLE,PRODUCT_RATING,OTHER_COMMENTS,CUSTOMER_ID,REVIEW_DATE)
VALUES(301,'xyz',null,null,103,'10-oct-21');



------memebership
insert into MEMBERSHIP(MEMBERSHIP_TYPE,USER_ID,START_DATE,DURATION)
VALUES('prime',null,null,null);

insert into MEMBERSHIP(MEMBERSHIP_TYPE,USER_ID,START_DATE,DURATION)
VALUES('platinum',null,null,null);


------cart product
insert into CART_PRODUCT(CART_ID,PRODUCT_ID)
VALUES(901,301);

insert into CART_PRODUCT(CART_ID,PRODUCT_ID)
VALUES(902,302);

insert into CART_PRODUCT(CART_ID,PRODUCT_ID)
VALUES(903,303);

