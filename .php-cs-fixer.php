<?php

declare(strict_types=1);

$finder = (new PhpCsFixer\Finder())
    ->in(__DIR__ . '/src')
    ->in(__DIR__ . '/tests');

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PSR12' => true,
        '@PhpCsFixer' => true,
        'declare_strict_types' => true,
        'native_function_invocation' => false,
        'php_unit_test_class_requires_covers' => false,
        'yoda_style' => false,
        'binary_operator_spaces' => ['default' => 'single_space'],
        'blank_line_before_statement' => true,
        'class_attributes_separation' => ['elements' => ['method' => 'one']],
    ])
    ->setFinder($finder);
