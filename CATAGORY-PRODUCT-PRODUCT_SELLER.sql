
--SEQUENCE FOR CATAGORY
CREATE SEQUENCE CATA_SEQ
    START WITH 2000
    INCREMENT BY 1;


--PROCEDURE TO ADD CATAGORY
CREATE OR REPLACE  PROCEDURE ADD_CATEGORY(CATEGORY_NAME1	VARCHAR2,
                                        SUBCATEGORY1	VARCHAR2)
IS
    CAT_ID NUMBER:= CATA_SEQ.NEXTVAL; 
BEGIN 
    INSERT INTO CATEGORIES VALUES(CAT_ID,CATEGORY_NAME1,SUBCATEGORY1,NULL);
    DBMS_OUTPUT.PUT_LINE('CATAGORY ADDED' );
END ADD_CATEGORY; 



--PACKAGE FOR  PRODUCT/PRODUCT_SELLER



CREATE OR REPLACE PACKAGE ADD_PRODUCT AS
    FUNCTION CHECK_SELLER(SELLER_ID1 VARCHAR) RETURN VARCHAR;
    FUNCTION CHECK_CATEGOY(CATEGORY_ID1 NUMBER) RETURN VARCHAR;
    FUNCTION FIND_PRODUCT_SELLER(PRODUCT_ID1 VARCHAR,SELLER_ID1 VARCHAR) RETURN VARCHAR;
END ADD_PRODUCT;   


CREATE OR REPLACE PACKAGE  BODY ADD_PRODUCT AS
    FUNCTION CHECK_SELLER(SELLER_ID1 VARCHAR) --TO CHECK SELLER EXIST OR NOT
    RETURN VARCHAR
    AS
        NAME1 VARCHAR(50);
    BEGIN
        SELECT SELLER_NAME INTO NAME1 FROM SELLER WHERE SELLER_ID LIKE SELLER_ID1;
        RETURN NAME1;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                NAME1 := 'NA';
            RETURN NAME1;
    END CHECK_SELLER;
    
    
    FUNCTION CHECK_CATEGOY(CATEGORY_ID1 NUMBER) --TO CHECK CATAGORY EXIST OR NOT
    RETURN VARCHAR
    AS
        NAME1 VARCHAR(50);
    BEGIN
        SELECT CATEGORY_NAME INTO NAME1 FROM CATEGORIES WHERE CATEGORY_ID LIKE CATEGORY_ID1;
        RETURN NAME1;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                NAME1 := 'NA';
            RETURN NAME1;
    END CHECK_CATEGOY;

    FUNCTION FIND_PRODUCT_SELLER(PRODUCT_ID1 VARCHAR,SELLER_ID1 VARCHAR) --TO FIND PRODUCT AND SELLER COMBINATION IN AVAILABE IN THE PRODUCT_SELLER TABLE
    RETURN VARCHAR
    AS
        NAME1 VARCHAR(50);
    BEGIN
        SELECT PRODUCT_ID INTO NAME1 FROM PRODUCT_SELLER WHERE PRODUCT_ID LIKE PRODUCT_ID1 AND SELLER_ID LIKE SELLER_ID1;
        RETURN NAME1;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                NAME1 := 'NA';
            RETURN NAME1;
    END FIND_PRODUCT_SELLER;
END ADD_PRODUCT;   


--PROCEDURE TO ADD/UPDATE PRODUCT AND PRODUCT_SELLER
CREATE OR REPLACE  PROCEDURE ADD_PRODUCT_SELLER(SELLER_ID1 VARCHAR2,CATEGORY_ID1 NUMBER,PRODUCT_NAME1 VARCHAR2,BRAND1 VARCHAR2,QUANTITY1 NUMBER,PRICE1 NUMBER,
                                DISCOUNT1 NUMBER,DISCOUNTED_PRICE1 NUMBER,DESCRIPTION1 VARCHAR2) 
IS
    T_PRICE CART.TOTAL_PRICE%TYPE;
    S_NAME SELLER.SELLER_NAME%TYPE;
    CH1 VARCHAR2(50);
    CH2 VARCHAR2(50);
    CH3 VARCHAR2(50);
    P_ID VARCHAR2(10);  
    QU NUMBER;
BEGIN
    CH1 := ADD_PRODUCT.CHECK_SELLER(SELLER_ID1);
    CH2 := ADD_PRODUCT.CHECK_CATEGOY(CATEGORY_ID1);
    IF CH1 != 'NA' AND CH2 != 'NA' THEN 
        SELECT PRODUCT_ID,QUANTITY INTO P_ID,QU FROM PRODUCT WHERE CATEGORY_ID LIKE CATEGORY_ID1 AND
        UPPER(PRODUCT_NAME) LIKE UPPER(PRODUCT_NAME1) AND UPPER(BRAND) LIKE UPPER(BRAND1);
        QU := QU+QUANTITY1;
        UPDATE PRODUCT SET QUANTITY = QU , PRICE = PRICE1,DISCOUNT = DISCOUNT1,
        DISCOUNTED_PRICE = DISCOUNTED_PRICE1,DESCRIPTION = DESCRIPTION1 WHERE PRODUCT_ID = P_ID;
        CH3 := ADD_PRODUCT.FIND_PRODUCT_SELLER(P_ID,SELLER_ID1);
        IF CH3 LIKE 'NA' THEN
            INSERT INTO PRODUCT_SELLER VALUES(P_ID,SELLER_ID1);
        END IF;
        
    ELSE
        DBMS_OUTPUT.put_line ('SELLER OR CATAGORY DOES NOT EXIST');
    END IF;
    EXCEPTION
    WHEN NO_DATA_FOUND THEN
        P_ID := PRODUCT_SEQ.NEXTVAL;
        INSERT INTO PRODUCT VALUES(P_ID,CATEGORY_ID1,PRODUCT_NAME1,BRAND1,QUANTITY1,PRICE1,DISCOUNT1,DISCOUNTED_PRICE1,DESCRIPTION1,NULL);
        INSERT INTO PRODUCT_SELLER VALUES(P_ID,SELLER_ID1);
        DBMS_OUTPUT.put_line ('PRODUCT ADDED SUCCESSFULLY');
END ADD_PRODUCT_SELLER;




