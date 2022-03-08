\c example_db;
CREATE TABLE public.article (
    id int GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    title text NOT NULL,
    content text NOT NULL,
    authorid int NOT NULL,
    status int DEFAULT 0,
    publishedat timestamp with time zone DEFAULT now()
);