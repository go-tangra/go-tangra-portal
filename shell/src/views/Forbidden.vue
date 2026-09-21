<template>
  <v-card class="pa-6 text-center" role="alert">
    <v-icon size="48" color="error" class="mb-4">mdi-shield-off-outline</v-icon>
    <h1 class="text-h5 mb-2">You do not have access to this page</h1>
    <p class="text-body-1">Ask an administrator for the required permission.</p>
    <v-btn class="mt-4" variant="text" to="/" data-test="home">Back to home</v-btn>
  </v-card>
</template>
