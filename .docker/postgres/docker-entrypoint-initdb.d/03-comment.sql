\c example_db;
CREATE TABLE public.comment (
    id int GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    title text NOT NULL,
    comment text NOT NULL,
    userid int NOT NULL,
    articleid int NOT NULL,
    publishedat timestamp with time zone DEFAULT now()
);