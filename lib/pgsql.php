<?php

namespace Pg;

class Db
{
    private $db;
    private static $statementCounter = 0;

    public function __construct($dsn)
    {
        $db = pg_connect($dsn);
        if ($db === false) {
            throw new \Exception('Could not connect: ' . pg_last_error());
        }
    }

    private function fetchResult($result)
    {
        $row = pg_fetch_assoc($result);
        if ($row !== false) {
            foreach ($row as $key => &$value) {
                $type = pg_field_type($result, pg_field_num($result, $key));
                switch ($type) {
                    case 'bool':
                        $value = ($value === 't');
                        break;
                    case 'int2':
                    case 'int4':
                        if ($value !== null) {
                            $value = intval($value);
                        }
                        break;
                    case '_int4': {
                        $matches = [];
                        preg_match('/^{(.*)}$/', $value, $matches);
                        $value = [];
                        if (count($matches) == 0) {
                            $value = null;
                        } elseif (strlen(trim($matches[1])) > 0) {
                            $value = str_getcsv($matches[1]);
                        }

                        break;
                    }
                }
            }
        }
        return $row;
    }

    public function fetch($query, $params = [], $func = null)
    {
        $result = $this->execute($query, $params);
        $rows = [];
        while ($row = $this->fetchResult($result)) {
            if ($func !== null) {
                $func($row);
            } else {
                array_push($rows, $row);
            }
        }
        if ($func === null) {
            return $rows;
        }
    }

    public function fetchRow($query, $params = [], $func = null)
    {
        $result = $this->execute($query, $params);
        $row = $this->fetchResult($result);
        if ($func !== null) {
            $func($row);
        }
        if ($func === null) {
            return $row;
        }
    }

    public function execute($query, $params = [])
    {
        self::$statementCounter++;
        $stmt = 'pg_db_stmt_' . self::$statementCounter;
        if (pg_prepare($stmt, $query) === false) {
            throw new \Exception("pg_prepare failed: " . pg_last_error());
        }

        foreach ($params as &$param) {
            if (is_bool($param)) {
                $param = $param ? 't' : 'f';
            } elseif (is_array($param)) {
                $temp = '{';
                foreach ($param as $item) {
                    if (is_string($item)) {
                        $temp .= '"' . $item . '"';
                    } else {
                        $temp .= $item;
                    }

                    $temp .= ',';
                }
                $temp = rtrim($temp, ',');
                $temp .= '}';
                $param = $temp;
            }
        }
        unset($param);

        $result = pg_execute($stmt, $params);
        if ($result === false) {
            throw new \Exception("pg_execute failed: " . pg_last_error());
        }

        return $result;
    }

    public function transaction($function)
    {
        $result = pg_query('BEGIN');
        if ($result === false) {
            throw new \Exception(
                'Could not start transaction: ' . pg_last_error()
            );
        }

        try {
            $function();

            $result = pg_query('COMMIT');
            if ($result === false) {
                throw new \Exception(
                    'Could not commit transaction: ' . pg_last_error()
                );
            }
        } catch (\Exception $e) {
            $result = pg_query('ROLLBACK');
            if ($result === false) {
                throw new \Exception(
                    'Could not rollback transaction: ' . pg_last_error()
                );
            }

            throw $e;
        }
    }

    public function affectedRows($result)
    {
        return pg_affected_rows($result);
    }

    public function prepare($query)
    {
        self::$statementCounter++;
        $stmt = 'pg_db_stmt_' . self::$statementCounter;

        if (pg_prepare($stmt, $query) === false) {
            throw new \Exception("pg_prepare failed: " . pg_last_error());
        }
        return $stmt;
    }

    public function executeWithPrepared($stmt, $params = [], $return = false)
    {
        foreach ($params as &$param) {
            if (is_bool($param)) {
                $param = $param ? 't' : 'f';
            } elseif (is_array($param)) {
                $temp = '{';
                foreach ($param as $item) {
                    if (is_string($item)) {
                        $temp .= '"' . $item . '"';
                    } else {
                        $temp .= $item;
                    }

                    $temp .= ',';
                }
                $temp = rtrim($temp, ',');
                $temp .= '}';
                $param = $temp;
            }
        }
        unset($param);

        $result = pg_execute($stmt, $params);

        if ($result === false) {
            throw new \Exception("pg_execute failed: " . pg_last_error());
        }
        
        if($return) {
            return $result;
        }

        $rows = [];
        while ($row = $this->fetchResult($result)) {
            array_push($rows, $row);
        }
        return $rows;
    }
}
