<?php
declare(strict_types=1);

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\App;
use Slim\Interfaces\RouteCollectorProxyInterface as Group;
use \Firebase\JWT\JWT;
use App\Application\Middleware\JwtAuthMiddleware;
use Respect\Validation\Validator as V;

/**
 * @OA\Info(
 *      title="Article API",
 *      version="1.0.1",
 *      contact={
 *          "email": "blt-hkn@hotmail.com"
 *      }
 * )
 * @OA\SecurityScheme(
 *      securityScheme="bearerAuth",
 *      in="header",
 *      name="bearerAuth",
 *      type="http",
 *      scheme="bearer",
 *      bearerFormat="JWT",
 * )
 */
return function (App $app) {
    $app->options('/{routes:.*}', function (Request $request, Response $response) {
        // CORS Pre-Flight OPTIONS Request Handler
        return $response;
    });
   
    $app->get('/', function (Request $request, Response $response) {
        $response->getBody()->write(json_encode(array('result' => true)));
        return $response
            ->withHeader('Content-Type', 'application/json');
    });

    /**
     * 
     * @OA\Post(
     *     path="/register",
     *     summary="Create a new user",
     *     tags={"Register"},
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         description="Sign up",
     *         required=true,
     *         request = "/register",
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                  @OA\Property(
     *                      property="username",
     *                      type="string"
     *                  ),
     *                  @OA\Property(
     *                      property="email",
     *                      type="string",
     *                      format="email"
     *                  ),
     *                  @OA\Property(
     *                      property="password",
     *                      type="password",
     *                      format="password",
     *                      minLength=4
     *                  )
     *             )
     *         ),
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                  @OA\Property(
     *                      property="username",
     *                      type="string"
     *                  ),
     *                  @OA\Property(
     *                      property="email",
     *                      type="string"
     *                  ),
     *                  @OA\Property(
     *                      property="password",
     *                      type="string"
     *                  )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response="200",
     *         description="Successfully registered.",
     *         @OA\JsonContent(
     *              @OA\Property(
     *                  property="userid",
     *                  type="string"
     *              )
     *        )
     *     ),
     *     @OA\Response(
     *         response="422",
     *         description="Something went wrong",
     *         @OA\JsonContent(
     *              @OA\Property(
     *                  property="errorMessage",
     *                  type="string"
     *              )
     *        )
     *     )
     * )
     */
    $app->post('/register', function (Request $request, Response $response) {
        $data = $request->getParsedBody();
        $db = $this->get('db');
        $validator = $this->get('validator');
        try {
            $validator->request($request, [
                'username' => V::notBlank(),
                'email' => V::email(),
                'password' => V::length(4)
            ]);
            if (!$validator->isValid()) {
                $errors = $validator->getErrors();
                throw new Exception(json_encode($errors), 1);
            }
            $query = 'SELECT id FROM public."user" WHERE username = $1 or email = $2 LIMIT 1';
            $user = $db->fetchRow($query, [ $data['username'], $data['email'] ]);
            if(!$user) {
                $query = 'INSERT INTO public."user"
                    (email, username, "password")
                    VALUES($1, $2, $3) RETURNING id';
                $user = $db->fetchRow($query, [ $data['email'], $data['username'], md5($data['password']) ]);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'userid' => $user['id']
                            )
                        )
                    );
            } else {
                throw new Exception('Girilen kullanıcı adı veya e-mail müsait değil!');
            }
        } catch(\Exception $e) {
            $response = $response->withStatus(422);
            $response
                ->getBody()
                ->write(
                    json_encode(
                        array(
                            'errorMessage' => $e->getMessage()
                        )
                    )
                );
        } finally {
            return $response
                ->withHeader('Content-Type', 'application/json');
        }
    });

    /**
     * 
     * @OA\Post(
     *     path="/login",
     *     summary="Get JWT token",
     *     tags={"Login"},
     *     @OA\RequestBody(
     *         description="Sign in",
     *         required=true,
     *         request = "/login",
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                  @OA\Property(
     *                      property="username",
     *                      type="string"
     *                  ),
     *                  @OA\Property(
     *                      property="password",
     *                      type="password",
     *                      format="password"
     *                  )
     *             )
     *         ),
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                  @OA\Property(
     *                      property="username",
     *                      type="string"
     *                  ),
     *                  @OA\Property(
     *                      property="password",
     *                      type="string",
     *                      format="password"
     *                  )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response="200",
     *         description="Successfully logged in.",
     *         @OA\JsonContent(
     *              @OA\Property(
     *                  property="token",
     *                  type="string"
     *              )
     *        )
     *     ),
     *     @OA\Response(
     *         response="422",
     *         description="Something went wrong",
     *         @OA\JsonContent(
     *              @OA\Property(
     *                  property="errorMessage",
     *                  type="string"
     *              )
     *        )
     *     )
     * )
     */
    $app->post('/login', function (Request $request, Response $response) {
        $data = $request->getParsedBody();
        $db = $this->get('db');
        $validator = $this->get('validator');
        try {
            $validator->request($request, [
                'username' => V::notBlank(),
                'password' => V::notBlank()
            ]);
            if (!$validator->isValid()) {
                $errors = $validator->getErrors();
                throw new Exception(json_encode($errors), 1);
            }
            $query =
                '
                    SELECT
                        u.id, u.email, u.username, u."password", u.token, u.tokenexpire
                    FROM "user" u
                    WHERE username = $1 LIMIT 1
                ';
            $user = $db->fetchRow($query, [$data['username']]);
            
            if($user && $user['password'] == md5($data['password'])) {
                $exp = date("Y-m-d H:i:s", time() + 60 * 60);
                
                if( !is_null($user['tokenexpire']) && strtotime($user['tokenexpire']) > strtotime( date("Y-m-d H:i:s", time()))) {
                    $jwt = $user["token"];
                } else {
                    $exp = date("Y-m-d H:i:s", time() + 60 * 60);
                    $secretkey = $this->get('settings')['secret_key'];
                    unset($user['token']);
                    unset($user['password']);
                    unset($user['tokenexpire']);
                    $payload = array(
                        'iss' => $user['id'],
                        'exp' => strtotime($exp),
                        'username' => $user['username'],
                        'email' => $user['email']
                    );
                    $jwt = JWT::encode($payload, $secretkey);
                    $query = 'UPDATE public."user" SET "token"= $1, tokenexpire = $2 WHERE id=$3';
                    $db->execute($query, [ $jwt, $exp, $user['id'] ]);
                }
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'token' => $jwt
                            )
                        )
                    );
            } else {
                throw new Exception('Girilen bilgiler hatalı!');
            }
        } catch(\Exception $e) {
            $response = $response->withStatus(422);
            $response
                ->getBody()
                ->write(
                    json_encode(
                        array(
                            'errorMessage' => $e->getMessage()
                        )
                    )
                );
        } finally {
            return $response
                ->withHeader('Content-Type', 'application/json');
        }
    });

    $app->group('/users', function (Group $group) {
        /**
         * 
         * @OA\Get(
         *     path="/users",
         *     summary="Get all users",
         *     tags={"Users"},
         *     security={{"bearerAuth":{}}},
         *     @OA\Response(
         *         response="200",
         *         description="Users list as array",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="users",
         *                  type="array",
         *                  @OA\Items(
         *                      @OA\Property(
         *                          property="id",
         *                          type="integer"
         *                      ),
         *                      @OA\Property(
         *                          property="email",
         *                          type="string"
         *                      ),
         *                      @OA\Property(
         *                          property="username",
         *                          type="string"
         *                      ),
         *                      @OA\Property(
         *                          property="identitynumber",
         *                          type="string"
         *                      )
         *                  )
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->get('', function (Request $request, Response $response) {
            $db = $this->get('db');
            try {
                $query = 'SELECT id, email, username  FROM "user"';
                $users = $db->fetch($query);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'users' => $users
                            )
                        )
                    );
            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
        /**
         * 
         * @OA\Get(
         *     path="/users/{id}",
         *     summary="Get specified user by id",
         *     tags={"Users"},
         *     security={{"bearerAuth":{}}},
         *     @OA\Parameter(
         *          name="id",
         *          in="path",
         *          required=true,
         *          description="The user ID",
         *          @OA\Schema(
         *              type="integer"
         *          ),
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Users list as array",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="user",
         *                  type="object",
         *                  @OA\Property(
         *                      property="id",
         *                      type="integer"
         *                  ),
         *                  @OA\Property(
         *                      property="email",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="username",
         *                      type="string"
         *                  )
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->get('/{id}', function (Request $request, Response $response, $args) {
            $db = $this->get('db');
            try {
                $userId = (int) $args['id'];
                $query = 'SELECT id, email, username  FROM "user" WHERE id = $1';
                $user = $db->fetchRow($query, [$userId]);
                if (!$user) {
                    throw new Exception('Kullanıcı bulunamadı!');
                }

                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'user' => $user
                            )
                        )
                    );

            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
        /**
         * 
         * @OA\Put(
         *     path="/users/{id}",
         *     summary="Update specified user by id",
         *     tags={"Users"},
         *     security={{"bearerAuth":{}}},
         *     @OA\Parameter(
         *          name="id",
         *          in="path",
         *          required=true,
         *          description="The user ID",
         *          @OA\Schema(
         *              type="integer"
         *          ),
         *     ),
         *     @OA\RequestBody(
         *         description="Update a user",
         *         required=true,
         *         request = "/register",
         *         @OA\MediaType(
         *             mediaType="application/json",
         *             @OA\Schema(
         *                  @OA\Property(
         *                      property="username",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="email",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="password",
         *                      type="string"
         *                  )
         *             )
         *         )
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Updated user ID",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="userid",
         *                  type="integer"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->put('/{id}', function (Request $request, Response $response, $args) {
            $db = $this->get('db');
            $validator = $this->get('validator');
            try {
                $userId = (int) $args['id'];
                $data = $request->getParsedBody();
                $validator->request($request, [
                    'username' => V::notBlank(),
                    'email' => V::email(),
                    'password' => V::length(4)
                ]);
                if (!$validator->isValid()) {
                    $errors = $validator->getErrors();
                    throw new Exception(json_encode($errors), 1);
                }
                $columns = [];
                $values = [];
                if (isset($data['password'])) {
                    $data['password'] = md5($data['password']);
                }
                foreach ($data as $key => $value) {
                   if (!empty($value)) {
                        array_push($columns, $key);
                        array_push($values, $value);
                   }
                }
                if (count($columns) == 0) {
                    throw new Exception('İstek verileri boş olamaz!');
                }
                if (count($columns) == 1) {
                    $query = 'UPDATE "user" SET ' . $columns[0] . ' = (\'' . $values[0] . '\') WHERE id = $1';
                } else {
                    $query = 'UPDATE "user" SET (' . implode(',', $columns) . ') = (\'' . implode('\',\'', $values) . '\') WHERE id = $1';
                }
                
                $user = $db->execute($query, [$userId]);
                if (!$user) {
                    throw new Exception('Güncelleme işlemi başarısız!');
                }

                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'userid' => $userId
                            )
                        )
                    );

            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
        /**
         * 
         * @OA\Delete(
         *     path="/users",
         *     summary="Delete specified user by id",
         *     tags={"Users"},
         *     security={{"bearerAuth":{}}},
         *     @OA\RequestBody(
         *         description="Delete a user",
         *         required=true,
         *         request = "/users",
         *         @OA\MediaType(
         *             mediaType="application/json",
         *             @OA\Schema(
         *                  @OA\Property(
         *                      property="id",
         *                      type="integer"
         *                  )
         *             )
         *         )
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Deleted user ID",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="userid",
         *                  type="integer"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->delete('', function (Request $request, Response $response) {
            $db = $this->get('db');
            try {
                $data = $request->getParsedBody();
                if (is_null($data) || !isset($data['id']) || empty($data['id'])) {
                    throw new Exception('Kullanıcı id boş olamaz!');
                }
                $userId = $data['id'];
                $query = 'DELETE FROM "user" WHERE id = $1';
                $user = $db->execute($query, [$userId]);
                if (!$user) {
                    throw new Exception('Kullanıcı bulunamadı!');
                }

                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'user' => $userId
                            )
                        )
                    );

            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
    })->add(JwtAuthMiddleware::class);

    $app->group('/articles', function (Group $group) {
        /**
         * 
         * @OA\Post(
         *     path="/articles",
         *     summary="Publish a new article",
         *     tags={"Article"},
         *     security={{"bearerAuth":{}}},
         *     @OA\RequestBody(
         *         description="Article Publish",
         *         required=true,
         *         request = "/articles",
         *         @OA\MediaType(
         *             mediaType="multipart/form-data",
         *             @OA\Schema(
         *                  @OA\Property(
         *                      property="title",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="content",
         *                      type="string"
         *                  )
         *             )
         *         ),
         *         @OA\MediaType(
         *             mediaType="application/json",
         *             @OA\Schema(
         *                  @OA\Property(
         *                      property="title",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="content",
         *                      type="string"
         *                  )
         *             )
         *         )
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Successfully created.",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="articleid",
         *                  type="integer"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->post('', function (Request $request, Response $response) {
            $data = $request->getParsedBody();
            $db = $this->get('db');
            $validator = $this->get('validator');
            try {
                $validator->request($request, [
                    'title' => V::notBlank(),
                    'content' => V::notBlank()
                ]);
                if (!$validator->isValid()) {
                    $errors = $validator->getErrors();
                    throw new Exception(json_encode($errors), 1);
                }
                $userid = $request->getAttribute('userid');
                $query = 'SELECT id FROM article WHERE title = $1 LIMIT 1';
                $article = $db->fetchRow($query, [ strtolower($data['title']) ]);
                
                if(!$article) {
                    $query = 'INSERT INTO article
                        (title, content, authorid)
                        VALUES($1, $2, $3) RETURNING id';
                    $article = $db->fetchRow($query, [ $data['title'], $data['content'], $userid ]);
                    $response
                        ->getBody()
                        ->write(
                            json_encode(
                                array(
                                    'articleid' => $article['id']
                                )
                            )
                        );
                } else {
                    throw new Exception('Girilen makale başlığı müsait değil!');
                }
            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
        /**
         * 
         * @OA\Get(
         *     path="/articles",
         *     summary="Get all article",
         *     tags={"Article"},
         *     security={{"bearerAuth":{}}},
         *     @OA\Response(
         *         response="200",
         *         description="Article list as array",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="article",
         *                  type="array",
         *                  @OA\Items(
         *                      @OA\Property(
         *                          property="id",
         *                          type="integer"
         *                      ),
         *                      @OA\Property(
         *                          property="title",
         *                          type="string"
         *                      ),
         *                      @OA\Property(
         *                          property="content",
         *                          type="string"
         *                      ),
         *                      @OA\Property(
         *                          property="status",
         *                          type="integer"
         *                      ),
         *                      @OA\Property(
         *                          property="authorid",
         *                          type="integer"
         *                      ),
         *                      @OA\Property(
         *                          property="publishedat",
         *                          type="string",
         *                          format="date-time"
         *                      )
         *                  )
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->get('', function (Request $request, Response $response) {
            $db = $this->get('db');
            try {
                $query = 'SELECT *  FROM article';
                $article = $db->fetch($query);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'article' => $article
                            )
                        )
                    );
            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
        /**
         * 
         * @OA\Get(
         *     path="/articles/{id}",
         *     summary="Get specified article by id",
         *     tags={"Article"},
         *     security={{"bearerAuth":{}}},
         *     @OA\Parameter(
         *          name="id",
         *          in="path",
         *          required=true,
         *          description="The article ID",
         *          @OA\Schema(
         *              type="integer"
         *          ),
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Article informations",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="article",
         *                  type="object",
         *                  @OA\Property(
         *                      property="id",
         *                      type="integer"
         *                  ),
         *                  @OA\Property(
         *                      property="title",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="content",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="status",
         *                      type="integer"
         *                  ),
         *                  @OA\Property(
         *                      property="authorid",
         *                      type="integer"
         *                  ),
         *                  @OA\Property(
         *                      property="publishedat",
         *                      type="string",
         *                      format="date-time"
         *                  )
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->get('/{id}', function (Request $request, Response $response, $args) {
            $db = $this->get('db');
            try {
                $articleId = (int) $args['id'];
                $query = 'SELECT * FROM article WHERE id = $1';
                $article = $db->fetchRow($query, [$articleId]);
                if (!$article) {
                    throw new Exception('Makale bulunamadı!');
                }

                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'article' => $article
                            )
                        )
                    );

            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
        /**
         * 
         * @OA\Put(
         *     path="/articles/{id}",
         *     summary="Update specified article by id",
         *     tags={"Article"},
         *     security={{"bearerAuth":{}}},
         *     @OA\Parameter(
         *          name="id",
         *          in="path",
         *          required=true,
         *          description="The article ID",
         *          @OA\Schema(
         *              type="integer"
         *          ),
         *     ),
         *     @OA\RequestBody(
         *         description="Update a article",
         *         required=true,
         *         request = "/register",
         *         @OA\MediaType(
         *             mediaType="application/json",
         *             @OA\Schema(
         *                  @OA\Property(
         *                      property="title",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="content",
         *                      type="string"
         *                  )
         *             )
         *         )
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Updated article ID",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="articleid",
         *                  type="integer"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->put('/{id}', function (Request $request, Response $response, $args) {
            $db = $this->get('db');
            $validator = $this->get('validator');
            try {
                $articleId = (int) $args['id'];
                $data = $request->getParsedBody();
                $validator->request($request, [
                    'title' => V::notBlank(),
                    'content' => V::notBlank()
                ]);
                if (!$validator->isValid()) {
                    $errors = $validator->getErrors();
                    throw new Exception(json_encode($errors), 1);
                }
                $userid = $request->getAttribute('userid');
                $query = 'SELECT id, authorid FROM article WHERE id = $1 LIMIT 1';
                $article = $db->fetchRow($query, [ $articleId]);
                if (!$article) {
                    throw new Exception('Böyle bir makale bulunamadı!');
                }
                if ($userid != $article['authorid']) {
                    throw new Exception('Farklı bir kullanıcıya ait makele düzenlenemez!');
                }
                $columns = [];
                $values = [];
                foreach ($data as $key => $value) {
                   if (!empty($value)) {
                        array_push($columns, $key);
                        array_push($values, $value);
                   }
                }
                if (count($columns) == 1) {
                    $query = 'UPDATE article SET ' . $columns[0] . ' = (\'' . $values[0] . '\') WHERE id = $1';
                } else {
                    $query = 'UPDATE article SET (' . implode(',', $columns) . ') = (\'' . implode('\',\'', $values) . '\') WHERE id = $1';
                }
                
                $article = $db->execute($query, [$articleId]);
                if (!$article) {
                    throw new Exception('Güncelleme işlemi başarısız!');
                }

                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'articleid' => $articleId
                            )
                        )
                    );

            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
        /**
         * 
         * @OA\Delete(
         *     path="/articles",
         *     summary="Delete specified article by id",
         *     tags={"Article"},
         *     security={{"bearerAuth":{}}},
         *     @OA\RequestBody(
         *         description="Delete a article",
         *         required=true,
         *         request = "/articles",
         *         @OA\MediaType(
         *             mediaType="application/json",
         *             @OA\Schema(
         *                  @OA\Property(
         *                      property="id",
         *                      type="integer"
         *                  )
         *             )
         *         )
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Deleted article ID",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="articleid",
         *                  type="integer"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->delete('', function (Request $request, Response $response) {
            try {
                $data = $request->getParsedBody();
                if (is_null($data) || !isset($data['id']) || empty($data['id'])) {
                    throw new Exception('Makale id boş olamaz!');
                }
                $articleId = $data['id'];
                $userid = $request->getAttribute('userid');
                $db = $this->get('db');
                $userid = $request->getAttribute('userid');
                $query = 'SELECT id, authorid FROM article WHERE id = $1 LIMIT 1';
                $article = $db->fetchRow($query, [ $articleId]);
                if (!$article) {
                    throw new Exception('Böyle bir makale bulunamadı!');
                }
                if ($userid != $article['authorid']) {
                    throw new Exception('Farklı bir kullanıcıya ait makele silinemez!');
                }
                
                $query = 'DELETE FROM article WHERE id = $1';
                $article = $db->execute($query, [$articleId]);

                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'article' => $articleId
                            )
                        )
                    );

            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
    })->add(JwtAuthMiddleware::class);

    $app->group('/articles/{articleid}/comments', function (Group $group) {
        /**
         * 
         * @OA\Post(
         *     path="/articles/{articleid}/comments",
         *     summary="Publish a new comment",
         *     tags={"Comment"},
         *     security={{"bearerAuth":{}}},
         *     @OA\Parameter(
         *          name="articleid",
         *          in="path",
         *          required=true,
         *          description="The article ID",
         *          @OA\Schema(
         *              type="integer"
         *          ),
         *     ),
         *     @OA\RequestBody(
         *         description="Comment Publish",
         *         required=true,
         *         request = "/articles/{articleid}/comments",
         *         @OA\MediaType(
         *             mediaType="multipart/form-data",
         *             @OA\Schema(
         *                  @OA\Property(
         *                      property="title",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="comment",
         *                      type="string"
         *                  )
         *             )
         *         ),
         *         @OA\MediaType(
         *             mediaType="application/json",
         *             @OA\Schema(
         *                  @OA\Property(
         *                      property="title",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="comment",
         *                      type="string"
         *                  )
         *             )
         *         )
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Successfully created.",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="commentid",
         *                  type="integer"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->post('', function (Request $request, Response $response, $args) {
            $data = $request->getParsedBody();
            $db = $this->get('db');
            $validator = $this->get('validator');
            try {
                $validator->request($request, [
                    'title' => V::notBlank(),
                    'comment' => V::notBlank(),
                ]);
                if (!$validator->isValid()) {
                    $errors = $validator->getErrors();
                    throw new Exception(json_encode($errors), 1);
                }
                $articleid = (int) $args['articleid'];

                $userid = $request->getAttribute('userid');
                $query = 'SELECT * FROM article WHERE id = $1';
                $article = $db->fetchRow($query, [$articleid]);
                if (!$article) {
                    throw new Exception('Makale bulunamadı!');
                }
                
                $query = 'INSERT INTO comment
                    (title, comment, userid, articleid)
                    VALUES($1, $2, $3, $4) RETURNING id';
                $comment = $db->fetchRow($query, [ $data['title'], $data['comment'], $userid, $articleid ]);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'commentid' => $comment['id']
                            )
                        )
                    );
            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
        /**
         * 
         * @OA\Get(
         *     path="/articles/{articleid}/comments",
         *     summary="Get comments by articleid",
         *     tags={"Comment"},
         *     security={{"bearerAuth":{}}},
         *     @OA\Parameter(
         *          name="articleid",
         *          in="path",
         *          required=true,
         *          description="The article ID",
         *          @OA\Schema(
         *              type="integer"
         *          ),
         *     ),
         *     @OA\Response(
         *         response="200",
         *         description="Comment list as array of specified article",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="comment",
         *                  type="object",
         *                  @OA\Property(
         *                      property="id",
         *                      type="integer"
         *                  ),
         *                  @OA\Property(
         *                      property="title",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="comment",
         *                      type="string"
         *                  ),
         *                  @OA\Property(
         *                      property="userid",
         *                      type="integer"
         *                  ),
         *                  @OA\Property(
         *                      property="articleid",
         *                      type="integer"
         *                  ),
         *                  @OA\Property(
         *                      property="publishedat",
         *                      type="string",
         *                      format="date-time"
         *                  )
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="422",
         *         description="Something went wrong",
         *         @OA\JsonContent(
         *              @OA\Property(
         *                  property="errorMessage",
         *                  type="string"
         *              )
         *        )
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Unauthorized"
         *     )
         * )
         */
        $group->get('', function (Request $request, Response $response, $args) {
            $db = $this->get('db');
            try {
                $articleid = (int) $args['articleid'];
                $query = 'SELECT * FROM article WHERE id = $1';
                $article = $db->fetchRow($query, [$articleid]);
                if (!$article) {
                    throw new Exception('Makale bulunamadı!');
                }
                $query = 'SELECT * FROM comment WHERE articleid = $1';
                $comments = $db->fetch($query, [$articleid]);

                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'comments' => $comments
                            )
                        )
                    );

            } catch(\Exception $e) {
                $response = $response->withStatus(422);
                $response
                    ->getBody()
                    ->write(
                        json_encode(
                            array(
                                'errorMessage' => $e->getMessage()
                            )
                        )
                    );
            } finally {
                return $response
                    ->withHeader('Content-Type', 'application/json');
            }
        });
    })->add(JwtAuthMiddleware::class);

    $app->get('/docs/v1', \App\Action\SwaggerUiAction::class);
};
