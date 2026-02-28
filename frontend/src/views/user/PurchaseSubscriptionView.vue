<template>
  <AppLayout>
    <div class="purchase-page-layout">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
            {{ t('purchase.title') }}
          </h2>
          <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
            {{ t('purchase.description') }}
          </p>
        </div>

        <div class="flex items-center gap-2">
          <a
            v-if="isValidUrl"
            :href="purchaseUrl"
            target="_blank"
            rel="noopener noreferrer"
            class="btn btn-secondary btn-sm"
          >
            <Icon name="externalLink" size="sm" class="mr-1.5" :stroke-width="2" />
            {{ t('purchase.openInNewTab') }}
          </a>
        </div>
      </div>

      <div class="card flex-1 min-h-0 overflow-hidden">
        <div v-if="loading" class="flex h-full items-center justify-center py-12">
          <div
            class="h-8 w-8 animate-spin rounded-full border-2 border-primary-500 border-t-transparent"
          ></div>
        </div>

        <div
          v-else-if="!purchaseEnabled"
          class="flex h-full items-center justify-center p-10 text-center"
        >
          <div class="max-w-md">
            <div
              class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 dark:bg-dark-700"
            >
              <Icon name="creditCard" size="lg" class="text-gray-400" />
            </div>
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
              {{ t('purchase.notEnabledTitle') }}
            </h3>
            <p class="mt-2 text-sm text-gray-500 dark:text-dark-400">
              {{ t('purchase.notEnabledDesc') }}
            </p>
          </div>
        </div>

        <div
          v-else-if="!isValidUrl"
          class="flex h-full items-center justify-center p-10 text-center"
        >
          <div class="max-w-md">
            <div
              class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 dark:bg-dark-700"
            >
              <Icon name="link" size="lg" class="text-gray-400" />
            </div>
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
              {{ t('purchase.notConfiguredTitle') }}
            </h3>
            <p class="mt-2 text-sm text-gray-500 dark:text-dark-400">
              {{ t('purchase.notConfiguredDesc') }}
            </p>
          </div>
        </div>

        <div v-else class="purchase-embed-shell">
          <iframe
            :src="purchaseUrl"
            class="purchase-embed-frame"
            allowfullscreen
          ></iframe>
        </div>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores'
import { useAuthStore } from '@/stores/auth'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'

const { t } = useI18n()
const appStore = useAppStore()
const authStore = useAuthStore()

const PURCHASE_USER_ID_QUERY_KEY = 'user_id'
const PURCHASE_THEME_QUERY_KEY = 'theme'
const PURCHASE_UI_MODE_QUERY_KEY = 'ui_mode'
const PURCHASE_UI_MODE_EMBEDDED = 'embedded'

const loading = ref(false)
const purchaseTheme = ref<'light' | 'dark'>('light')
let themeObserver: MutationObserver | null = null

const purchaseEnabled = computed(() => {
  return appStore.cachedPublicSettings?.purchase_subscription_enabled ?? false
})

function detectTheme(): 'light' | 'dark' {
  if (typeof document === 'undefined') return 'light'
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
}

function buildPurchaseUrl(baseUrl: string, userId?: number, theme: 'light' | 'dark' = 'light'): string {
  if (!baseUrl) return baseUrl
  try {
    const url = new URL(baseUrl)
    if (userId) {
      url.searchParams.set(PURCHASE_USER_ID_QUERY_KEY, String(userId))
    }
    url.searchParams.set(PURCHASE_THEME_QUERY_KEY, theme)
    url.searchParams.set(PURCHASE_UI_MODE_QUERY_KEY, PURCHASE_UI_MODE_EMBEDDED)
    return url.toString()
  } catch {
    const params: string[] = []
    if (userId) {
      params.push(`${PURCHASE_USER_ID_QUERY_KEY}=${encodeURIComponent(String(userId))}`)
    }
    params.push(`${PURCHASE_THEME_QUERY_KEY}=${encodeURIComponent(theme)}`)
    params.push(`${PURCHASE_UI_MODE_QUERY_KEY}=${encodeURIComponent(PURCHASE_UI_MODE_EMBEDDED)}`)
    const separator = baseUrl.includes('?') ? '&' : '?'
    return `${baseUrl}${separator}${params.join('&')}`
  }
}

const purchaseUrl = computed(() => {
  const baseUrl = (appStore.cachedPublicSettings?.purchase_subscription_url || '').trim()
  return buildPurchaseUrl(baseUrl, authStore.user?.id, purchaseTheme.value)
})

const isValidUrl = computed(() => {
  const url = purchaseUrl.value
  return url.startsWith('http://') || url.startsWith('https://')
})

onMounted(async () => {
  purchaseTheme.value = detectTheme()

  if (typeof document !== 'undefined') {
    themeObserver = new MutationObserver(() => {
      purchaseTheme.value = detectTheme()
    })
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    })
  }

  if (appStore.publicSettingsLoaded) return
  loading.value = true
  try {
    await appStore.fetchPublicSettings()
  } finally {
    loading.value = false
  }
})

onUnmounted(() => {
  if (themeObserver) {
    themeObserver.disconnect()
    themeObserver = null
  }
})
</script>

<style scoped>
.purchase-page-layout {
  @apply flex flex-col gap-6;
  height: calc(100vh - 64px - 4rem);
}

.purchase-embed-shell {
  @apply h-full w-full overflow-auto rounded-2xl;
  @apply bg-gradient-to-b from-gray-50 to-white dark:from-dark-900 dark:to-dark-950;
  @apply p-3 sm:p-4;
}

.purchase-embed-frame {
  display: block;
  margin: 0 auto;
  width: min(100%, 440px);
  height: 840px;
  border: 0;
  border-radius: 16px;
  box-shadow: 0 8px 24px rgba(15, 23, 42, 0.14);
  background: transparent;
}

@media (max-width: 640px) {
  .purchase-embed-frame {
    width: 100%;
    height: 780px;
    border-radius: 12px;
  }
}
</style>
