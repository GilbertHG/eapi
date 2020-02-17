<?php

/** @var \Illuminate\Database\Eloquent\Factory $factory */

use App\Model\Product;
use Faker\Generator as Faker;

$factory->define(Product::class, function (Faker $faker) {
    return [
        'name'      => $faker->word,
        'detail'    => $faker->paragraph,
        'price'     => $faker->numberBetween(1000,999999999),
        'stock'     => $faker->randomDigit,
        'discount'  => $faker->numberBetween(2,30),
        'user_id'  => function(){
            return App\User::all()->random();
        },
    ];
});
