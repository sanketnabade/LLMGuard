# LLMGuard Frontend

A modern, responsive Next.js frontend for testing and validating content against LLMGuard security policies.

## Features

- 🛡️ **Content Validation**: Test messages against multiple security policies
- 🔍 **Real-time Feedback**: Immediate validation results with detailed information
- 🎨 **Modern UI**: Clean, responsive interface built with Tailwind CSS
- 📱 **Mobile Friendly**: Works seamlessly on all device sizes
- ⚡ **Fast**: Built with Next.js 14 and React 18
- 🔴 **Health Check**: Visual indicator of backend connection status

## Security Policies Tested

- **PII Detection**: Email addresses, phone numbers, SSN, credit cards, IP addresses, etc.
- **Toxicity Detection**: Identifies inappropriate or harmful language
- **Competitor Mentions**: Detects references to competitor companies
- **Prompt Injection**: Identifies attempts to manipulate system prompts

## Prerequisites

- Node.js 18.x or higher
- npm or yarn package manager
- LLMGuard backend running (default: http://localhost:8000)

## Installation

1. Navigate to the frontend directory:

```bash
cd frontend
```

2. Install dependencies:

```bash
npm install
# or
yarn install
```

3. Create a `.env.local` file (optional, for custom backend URL):

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Running the Application

### Development Mode

Start the development server:

```bash
npm run dev
# or
yarn dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Production Build

Build the application for production:

```bash
npm run build
npm start
# or
yarn build
yarn start
```

## Project Structure

```
frontend/
├── app/
│   ├── globals.css          # Global styles with Tailwind
│   ├── layout.tsx           # Root layout component
│   └── page.tsx             # Main page with validation UI
├── lib/
│   └── api.ts               # API client and types
├── public/                  # Static assets
├── next.config.js           # Next.js configuration
├── tailwind.config.js       # Tailwind CSS configuration
├── tsconfig.json            # TypeScript configuration
└── package.json             # Project dependencies
```

## Usage

1. **Enter Message**: Type or paste the content you want to validate in the message textarea
2. **Optional User ID**: Add a user identifier for tracking (optional)
3. **Validate**: Click the "Validate Content" button
4. **View Results**: See detailed validation results including:
   - Safety code (SAFE or specific violation)
   - Action to be taken (OVERRIDE, ANONYMIZE, WARN)
   - Processed content (if anonymization was applied)

### Quick Examples

The interface includes pre-loaded examples to quickly test different scenarios:

- PII Detection (email and phone)
- Credit Card & SSN detection
- Toxic content detection
- Prompt injection attempts
- Competitor mentions
- Safe content baseline

## API Integration

The frontend connects to the LLMGuard backend via the `/safeguard` endpoint.

### Request Format:

```json
{
  "messages": [
    {
      "role": "user",
      "content": "Your message here"
    }
  ],
  "user_id": "optional-user-id"
}
```

### Response Format:

```json
{
  "safety_code": "SAFE",
  "message": "Content is safe",
  "action": "0",
  "processed_content": "Anonymized content (if applicable)"
}
```

## Configuration

### Backend URL

By default, the frontend connects to `http://localhost:8000`. To change this:

1. Create a `.env.local` file in the frontend directory
2. Set the `NEXT_PUBLIC_API_URL` environment variable:

```env
NEXT_PUBLIC_API_URL=https://your-backend-url.com
```

### Styling

The application uses Tailwind CSS for styling. You can customize:

- Colors and themes in `tailwind.config.js`
- Global styles in `app/globals.css`
- Component-specific styles in `app/page.tsx`

## Development

### Adding New Features

1. **API Types**: Add new types to `lib/api.ts`
2. **Components**: Create reusable components in a new `components/` directory
3. **Pages**: Add new pages in the `app/` directory

### Code Style

- TypeScript is used throughout the project
- ESLint is configured for code quality
- Follow React and Next.js best practices

## Troubleshooting

### Backend Connection Issues

If you see "Backend: Offline":

1. Ensure the LLMGuard backend is running on port 8000
2. Check CORS settings in the backend
3. Verify the `NEXT_PUBLIC_API_URL` in your `.env.local`

### Build Errors

If you encounter build errors:

1. Delete `node_modules` and `.next` directories
2. Run `npm install` again
3. Clear Next.js cache: `rm -rf .next`

### TypeScript Errors

If TypeScript shows errors:

1. Ensure all dependencies are installed
2. Run `npm run build` to see detailed error messages
3. Check `tsconfig.json` configuration

## Browser Support

- Chrome/Edge (latest 2 versions)
- Firefox (latest 2 versions)
- Safari (latest 2 versions)
- Mobile browsers (iOS Safari, Chrome Mobile)

## License

This project is part of the LLMGuard security suite.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues or questions:

- Open an issue in the GitHub repository
- Check the main LLMGuard documentation
- Review the backend API documentation
